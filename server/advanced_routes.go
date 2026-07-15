package server

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/nitish-mp3/simson-vps/asterisk"
	"github.com/nitish-mp3/simson-vps/calls"
	"github.com/nitish-mp3/simson-vps/protocol"
	"github.com/nitish-mp3/simson-vps/store"
)

type advancedRouteEvent struct {
	legID  string
	target store.RouteTarget
	ok     bool
	reason string
}

type advancedRouteLeg struct {
	parentID string
	target   store.RouteTarget
	answered bool
}

type advancedRouteRun struct {
	mu            sync.Mutex
	parentID      string
	accountID     string
	bridgeID      string
	sourceChannel string
	plan          store.AdvancedRoute
	events        chan advancedRouteEvent
	children      map[string]*advancedRouteLeg
	invitedNodes  map[string]bool
	answered      map[string]bool
	winner        string
	conference    bool
	closed        bool
}

func (s *Server) tryStartAdvancedRoute(accountID, sourceExt string, in asterisk.IncomingSIPCall) bool {
	if s.asterisk == nil || accountID == "" || sourceExt == "" {
		return false
	}
	var plan *store.AdvancedRoute
	var err error
	for _, kind := range []string{"gateway", "sip"} {
		plan, err = s.store.GetAdvancedRouteByIngress(accountID, kind, sourceExt)
		if err != nil {
			s.log.Error("advanced route lookup failed", map[string]any{
				"account_id": accountID, "source": sourceExt, "kind": kind, "err": err.Error(),
			})
			return false
		}
		if plan != nil {
			break
		}
	}
	if plan == nil || !plan.Enabled {
		return false
	}

	callID := "call_" + uuid.NewString()
	call := &calls.Call{
		ID: callID, FromNode: "sip:" + sourceExt, ToNode: "route:" + plan.ID,
		AccountID: accountID, CallType: "sip", SIPBridgeID: in.BridgeID, CallerID: in.CallerID,
	}
	if !s.calls.Create(call) {
		return true
	}
	run := &advancedRouteRun{
		parentID: callID, accountID: accountID, bridgeID: in.BridgeID,
		sourceChannel: in.Channel, plan: *plan, events: make(chan advancedRouteEvent, 64),
		children: make(map[string]*advancedRouteLeg), invitedNodes: make(map[string]bool),
		answered: make(map[string]bool),
	}
	s.asterisk.TrackCall(callID, in.Channel)
	s.advancedRoutesMu.Lock()
	s.advancedRoutes[callID] = run
	s.advancedRoutesMu.Unlock()

	s.store.WriteAudit(accountID, "sip:"+sourceExt, "advanced_route_started",
		fmt.Sprintf("call=%s route=%s bridge=%s", callID, plan.ID, in.BridgeID), "")
	s.log.Info("advanced SIP route started", map[string]any{
		"call_id": callID, "route_id": plan.ID, "route": plan.Name, "source": sourceExt,
	})
	go s.executeAdvancedRoute(run, in, sourceExt)
	return true
}

func (s *Server) executeAdvancedRoute(run *advancedRouteRun, in asterisk.IncomingSIPCall, sourceExt string) {
	for stageIndex, stage := range run.plan.Stages {
		if s.advancedRouteClosed(run) {
			return
		}
		// Never degrade a private hub into a shared conference. Older or manually
		// edited databases may bypass API validation, so enforce isolation here too.
		if stage.AnswerMode == "private_hub" {
			s.log.Error("private hub route blocked without isolated-media capability", map[string]any{
				"call_id": run.parentID, "route_id": run.plan.ID, "stage": stageIndex + 1,
			})
			s.endAdvancedRoute(run, "private_hub_unavailable", true)
			return
		}
		activeTargets := 0
		run.mu.Lock()
		run.conference = stage.AnswerMode == "conference"
		run.mu.Unlock()
		for _, target := range stage.Targets {
			if !target.Enabled || target.Value == "" {
				continue
			}
			switch target.Kind {
			case "haos":
				if s.inviteAdvancedRouteNode(run, target, in, sourceExt, stageIndex) {
					activeTargets++
				}
			case "sip", "gateway", "external":
				if s.originateAdvancedRouteLeg(run, target, in, sourceExt, stage.RingSeconds) {
					activeTargets++
				}
			}
		}
		if activeTargets == 0 {
			continue
		}

		timer := time.NewTimer(time.Duration(stage.RingSeconds) * time.Second)
		stageAnswered := 0
	waitStage:
		for {
			select {
			case event := <-run.events:
				if !event.ok {
					continue
				}
				run.mu.Lock()
				if !run.answered[event.legID] {
					run.answered[event.legID] = true
					stageAnswered++
				}
				if run.winner == "" {
					run.winner = event.legID
				}
				run.mu.Unlock()
				if stage.AnswerMode == "first_answer" {
					timer.Stop()
					s.activateAdvancedRoute(run, event.legID, "sip:"+event.target.Value)
					return
				}
				if stageAnswered >= stage.MaxAnswered {
					timer.Stop()
					s.activateAdvancedRoute(run, "", "conference")
					return
				}
			case <-timer.C:
				break waitStage
			}
		}
		if stageAnswered > 0 {
			s.activateAdvancedRoute(run, "", "conference")
			return
		}
		s.cancelAdvancedRoutePending(run, "stage_timeout")
	}
	s.endAdvancedRoute(run, "route_exhausted", true)
}

func (s *Server) inviteAdvancedRouteNode(run *advancedRouteRun, target store.RouteTarget, in asterisk.IncomingSIPCall, sourceExt string, stageIndex int) bool {
	sess := s.hub.Get(target.Value)
	if sess == nil || sess.AccountID != run.accountID {
		return false
	}
	if _, ok := s.calls.AddInvitee(run.parentID, target.Value); !ok {
		return false
	}
	run.mu.Lock()
	run.invitedNodes[target.Value] = true
	run.mu.Unlock()
	metadata, _ := json.Marshal(map[string]any{
		"sip_bridge_id": in.BridgeID, "sip_channel": in.Channel,
		"sip_source_extension": sourceExt, "advanced_route_id": run.plan.ID,
		"advanced_route_stage": stageIndex + 1,
	})
	invite := protocol.NewEnvelope(protocol.TypeCallInvite, protocol.CallInvitePayload{
		CallID: run.parentID, FromNodeID: "sip:" + sourceExt,
		FromLabel: firstNonBlank(in.CallerID, sourceExt), CallType: "sip", Metadata: metadata,
	})
	data, _ := invite.Encode()
	sess.Send(data)
	return true
}

func (s *Server) originateAdvancedRouteLeg(run *advancedRouteRun, target store.RouteTarget, in asterisk.IncomingSIPCall, sourceExt string, timeout int) bool {
	if target.Kind != "external" && !s.asterisk.EndpointHasContacts(target.Value) {
		return false
	}
	legID := "route_leg_" + uuid.NewString()
	leg := &advancedRouteLeg{parentID: run.parentID, target: target}
	run.mu.Lock()
	run.children[legID] = leg
	run.mu.Unlock()
	s.advancedRoutesMu.Lock()
	s.advancedRouteLeg[legID] = leg
	s.advancedRoutesMu.Unlock()

	callerID := formatSIPCallerID(firstNonBlank(in.CallerID, run.plan.Name), sourceExt)
	var err error
	if target.Kind == "external" {
		_, err = s.asterisk.OriginateToTrunk(
			target.Value, target.Trunk, s.cfg.Asterisk.OutContext,
			s.cfg.Asterisk.NodeContext, run.bridgeID, callerID, legID,
			"route:"+run.plan.ID, "", "", timeout,
		)
	} else {
		_, err = s.asterisk.OriginateToExtension(
			target.Value, s.cfg.Asterisk.NodeContext, run.bridgeID,
			callerID, legID, "route:"+run.plan.ID, timeout,
		)
	}
	if err != nil {
		s.removeAdvancedRouteLeg(legID)
		s.log.Warn("advanced route originate failed", map[string]any{
			"call_id": run.parentID, "target": target.Value, "kind": target.Kind, "err": err.Error(),
		})
		return false
	}
	return true
}

func (s *Server) handleAdvancedRouteOriginateResult(legID string, ok bool, reason string) bool {
	s.advancedRoutesMu.Lock()
	leg := s.advancedRouteLeg[legID]
	var run *advancedRouteRun
	if leg != nil {
		run = s.advancedRoutes[leg.parentID]
	}
	s.advancedRoutesMu.Unlock()
	if leg == nil {
		return false
	}
	if run == nil {
		s.removeAdvancedRouteLeg(legID)
		return true
	}
	if ok {
		run.mu.Lock()
		if current := run.children[legID]; current != nil {
			current.answered = true
		}
		run.mu.Unlock()
	}
	select {
	case run.events <- advancedRouteEvent{legID: legID, target: leg.target, ok: ok, reason: reason}:
	default:
		s.log.Warn("advanced route event queue full", map[string]any{"call_id": run.parentID, "leg_id": legID})
	}
	return true
}

func (s *Server) claimAdvancedRouteHAOSAnswer(callID, nodeID string) {
	s.advancedRoutesMu.Lock()
	run := s.advancedRoutes[callID]
	s.advancedRoutesMu.Unlock()
	if run == nil {
		return
	}
	run.mu.Lock()
	if run.closed || !run.invitedNodes[nodeID] || run.winner != "" {
		run.mu.Unlock()
		return
	}
	run.winner = "haos:" + nodeID
	run.answered[run.winner] = true
	run.mu.Unlock()
	select {
	case run.events <- advancedRouteEvent{
		legID:  run.winner,
		target: store.RouteTarget{Kind: "haos", Value: nodeID},
		ok:     true,
	}:
	default:
		go s.cancelAdvancedRouteLosers(run, run.winner)
	}
}

func (s *Server) activateAdvancedRoute(run *advancedRouteRun, winner, answeredBy string) {
	if winner != "" {
		run.mu.Lock()
		if run.winner == "" {
			run.winner = winner
		}
		run.mu.Unlock()
	}
	if call, ok := s.calls.Accept(run.parentID, ""); ok {
		s.notifyCallStatus(call)
	}
	s.cancelAdvancedRouteLosers(run, firstNonBlank(winner, run.winner))
	s.log.Info("advanced route answered", map[string]any{
		"call_id": run.parentID, "route_id": run.plan.ID, "answered_by": answeredBy,
	})
}

func (s *Server) cancelAdvancedRouteLosers(run *advancedRouteRun, winner string) {
	run.mu.Lock()
	type childState struct {
		leg      *advancedRouteLeg
		answered bool
	}
	children := make(map[string]childState, len(run.children))
	for id, leg := range run.children {
		children[id] = childState{leg: leg, answered: leg.answered}
	}
	invited := make([]string, 0, len(run.invitedNodes))
	for node := range run.invitedNodes {
		invited = append(invited, node)
	}
	conference := run.conference
	run.mu.Unlock()
	for id, child := range children {
		// First-answer mode keeps only the winner. Conference mode keeps every
		// leg that actually answered, but immediately stops any still-ringing
		// leg once the participant limit or stage timeout is reached.
		keep := (!conference && id == winner) || (conference && child.answered)
		if !keep {
			_ = s.asterisk.HangupCall(id)
			s.removeAdvancedRouteLeg(id)
		}
	}
	for _, node := range invited {
		if "haos:"+node == winner {
			continue
		}
		if call := s.calls.Get(run.parentID); call != nil {
			s.notifyCallStatusToNode(node, call, string(calls.StateEnded), "answered_elsewhere", "")
			s.calls.RemoveInvitee(run.parentID, node)
		}
	}
}

func (s *Server) cancelAdvancedRoutePending(run *advancedRouteRun, reason string) {
	run.mu.Lock()
	children := make([]string, 0, len(run.children))
	for id, leg := range run.children {
		if !leg.answered {
			children = append(children, id)
		}
	}
	invited := make([]string, 0, len(run.invitedNodes))
	for node := range run.invitedNodes {
		invited = append(invited, node)
	}
	run.invitedNodes = make(map[string]bool)
	run.mu.Unlock()
	for _, id := range children {
		_ = s.asterisk.HangupCall(id)
		s.removeAdvancedRouteLeg(id)
	}
	for _, node := range invited {
		if call := s.calls.Get(run.parentID); call != nil {
			s.notifyCallStatusToNode(node, call, string(calls.StateEnded), reason, "")
			s.calls.RemoveInvitee(run.parentID, node)
		}
	}
}

func (s *Server) handleAdvancedRouteHangup(callID, channel string) bool {
	s.advancedRoutesMu.Lock()
	run := s.advancedRoutes[callID]
	leg := s.advancedRouteLeg[callID]
	if run == nil && leg != nil {
		run = s.advancedRoutes[leg.parentID]
	}
	s.advancedRoutesMu.Unlock()
	if run == nil && leg == nil {
		return false
	}
	if leg != nil {
		run.mu.Lock()
		wasAnswered := leg.answered
		run.mu.Unlock()
		s.removeAdvancedRouteLeg(callID)
		if !wasAnswered {
			select {
			case run.events <- advancedRouteEvent{legID: callID, target: leg.target, ok: false, reason: "hangup"}:
			default:
			}
			return true
		}
		if run.conference {
			run.mu.Lock()
			delete(run.answered, callID)
			remaining := len(run.answered)
			run.mu.Unlock()
			if remaining > 0 {
				return true
			}
		}
	}
	go s.endAdvancedRoute(run, "sip_hangup", true)
	return true
}

func (s *Server) endAdvancedRoute(run *advancedRouteRun, reason string, hangupBridge bool) {
	if run == nil {
		return
	}
	run.mu.Lock()
	if run.closed {
		run.mu.Unlock()
		return
	}
	run.closed = true
	children := make([]string, 0, len(run.children))
	for id := range run.children {
		children = append(children, id)
	}
	run.mu.Unlock()
	if call, ok := s.calls.End(run.parentID, reason); ok {
		s.notifyCallStatus(call)
	}
	for _, id := range children {
		_ = s.asterisk.HangupCall(id)
		s.removeAdvancedRouteLeg(id)
	}
	if hangupBridge {
		_ = s.asterisk.HangupCall(run.parentID)
		if run.bridgeID != "" {
			_ = s.asterisk.HangupBridge(run.bridgeID, "")
		}
	}
	s.asterisk.UntrackCall(run.parentID)
	s.advancedRoutesMu.Lock()
	delete(s.advancedRoutes, run.parentID)
	s.advancedRoutesMu.Unlock()
	s.log.Info("advanced route ended", map[string]any{"call_id": run.parentID, "route_id": run.plan.ID, "reason": reason})
}

func (s *Server) removeAdvancedRouteLeg(legID string) {
	s.advancedRoutesMu.Lock()
	leg := s.advancedRouteLeg[legID]
	delete(s.advancedRouteLeg, legID)
	var run *advancedRouteRun
	if leg != nil {
		run = s.advancedRoutes[leg.parentID]
	}
	s.advancedRoutesMu.Unlock()
	if run != nil {
		run.mu.Lock()
		delete(run.children, legID)
		run.mu.Unlock()
	}
	if s.asterisk != nil {
		s.asterisk.UntrackCall(legID)
	}
}

func (s *Server) advancedRouteClosed(run *advancedRouteRun) bool {
	run.mu.Lock()
	defer run.mu.Unlock()
	return run.closed
}
