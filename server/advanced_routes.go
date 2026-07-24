package server

import (
	"encoding/json"
	"fmt"
	"strings"
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
	ingressExt    string
	sourceChannel string
	plan          store.AdvancedRoute
	events        chan advancedRouteEvent
	children      map[string]*advancedRouteLeg
	invitedNodes  map[string]bool
	answered      map[string]bool
	winner        string
	conference    bool
	closed        bool
	done          chan struct{}
}

// tryStartAdvancedRouteForIngress starts the plan identified by ingressExt,
// while retaining sourceExt as the real caller for loop protection, caller ID,
// and audit data. This distinction is important for landing routes: a call
// from 1027 to 1028 must be able to match a plan for 1028 without pretending
// that 1028 placed the call.
func (s *Server) tryStartAdvancedRouteForIngress(accountID, ingressExt, sourceExt string, in asterisk.IncomingSIPCall) bool {
	if s.asterisk == nil || accountID == "" || sourceExt == "" {
		return false
	}
	ingressExt = strings.TrimSpace(ingressExt)
	if ingressExt == "" {
		return false
	}
	var plan *store.AdvancedRoute
	var err error
	for _, kind := range []string{"gateway", "sip"} {
		plan, err = s.store.GetAdvancedRouteByIngress(accountID, kind, ingressExt)
		if err != nil {
			s.log.Error("advanced route lookup failed", map[string]any{
				"account_id": accountID, "ingress": ingressExt, "kind": kind, "err": err.Error(),
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
		ingressExt: ingressExt, sourceChannel: in.Channel, plan: *plan, events: make(chan advancedRouteEvent, 64),
		children: make(map[string]*advancedRouteLeg), invitedNodes: make(map[string]bool),
		answered: make(map[string]bool), done: make(chan struct{}),
	}
	s.asterisk.TrackCall(callID, in.Channel)
	s.advancedRoutesMu.Lock()
	s.advancedRoutes[callID] = run
	s.advancedRoutesMu.Unlock()

	s.store.WriteAudit(accountID, "sip:"+sourceExt, "advanced_route_started",
		fmt.Sprintf("call=%s route=%s ingress=%s bridge=%s", callID, plan.ID, ingressExt, in.BridgeID), "")
	s.log.Info("advanced SIP route started", map[string]any{
		"call_id": callID, "route_id": plan.ID, "route": plan.Name,
		"ingress": ingressExt, "source": sourceExt,
	})
	go s.executeAdvancedRoute(run, in, sourceExt)
	return true
}

func (s *Server) executeAdvancedRoute(run *advancedRouteRun, in asterisk.IncomingSIPCall, sourceExt string) {
	seenTargets := make(map[string]bool)
	for stageIndex, configuredStage := range run.plan.Stages {
		stage := advancedRouteStageWithLandingPhone(run, configuredStage, stageIndex, sourceExt)
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
		if reason := unsafeExternalAdvancedStage(run.plan, stage); reason != "" {
			s.log.Error("unsafe outside-number route blocked at runtime", map[string]any{
				"call_id": run.parentID, "route_id": run.plan.ID,
				"stage": stageIndex + 1, "reason": reason,
			})
			s.endAdvancedRoute(run, "unsafe_external_route", true)
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
			key := advancedRouteTargetKey(target)
			if seenTargets[key] {
				s.log.Warn("advanced route skipped repeated legacy target", map[string]any{
					"call_id": run.parentID, "route_id": run.plan.ID,
					"stage": stageIndex + 1, "kind": target.Kind, "target": target.Value,
				})
				continue
			}
			if (target.Kind == "sip" || target.Kind == "gateway") && target.Value == sourceExt {
				s.log.Warn("advanced route skipped ingress loop", map[string]any{
					"call_id": run.parentID, "route_id": run.plan.ID,
					"stage": stageIndex + 1, "target": target.Value,
				})
				continue
			}
			seenTargets[key] = true
			switch target.Kind {
			case "haos":
				if s.inviteAdvancedRouteNode(run, target, in, sourceExt, stageIndex) {
					activeTargets++
					s.log.Info("advanced route HAOS destination invited", map[string]any{
						"call_id": run.parentID, "route_id": run.plan.ID,
						"stage": stageIndex + 1, "target": target.Value,
					})
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
			case <-run.done:
				timer.Stop()
				return
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
					s.activateAdvancedRoute(run, event.legID, "sip:"+event.target.Value, stage.MaxCallSeconds)
					return
				}
				if stageAnswered >= stage.MaxAnswered {
					timer.Stop()
					s.activateAdvancedRoute(run, "", "conference", stage.MaxCallSeconds)
					return
				}
			case <-timer.C:
				break waitStage
			}
		}
		if stageAnswered > 0 {
			s.activateAdvancedRoute(run, "", "conference", stage.MaxCallSeconds)
			return
		}
		s.cancelAdvancedRoutePending(run, "stage_timeout")
	}
	s.endAdvancedRoute(run, "route_exhausted", true)
}

// advancedRouteStageWithLandingPhone guarantees the basic PBX contract for a
// SIP landing route: calling the configured extension must ring that phone.
// Older plans could omit the landing phone because the UI treated every stage
// as fallback-only; those plans silently parked the caller until another stage
// ran. Keep explicitly configured parallel destinations, but add the landing
// endpoint to stage one when it is safe and not already present.
func advancedRouteStageWithLandingPhone(run *advancedRouteRun, stage store.RouteStage, stageIndex int, sourceExt string) store.RouteStage {
	if run == nil || stageIndex != 0 || run.plan.IngressKind != "sip" {
		return stage
	}
	landing := strings.TrimSpace(run.ingressExt)
	if landing == "" || landing == strings.TrimSpace(sourceExt) {
		return stage
	}
	for _, target := range stage.Targets {
		if target.Enabled && (target.Kind == "sip" || target.Kind == "gateway") && strings.TrimSpace(target.Value) == landing {
			return stage
		}
	}
	stage.Targets = append([]store.RouteTarget{{
		ID: "landing_" + landing, Kind: "sip", Value: landing,
		Label: "Landing phone", Enabled: true,
	}}, stage.Targets...)
	return stage
}

// unsafeExternalAdvancedStage is a runtime safety net for plans that predate
// API validation or were edited directly in SQLite. Analog gateways commonly
// answer SIP as soon as they seize a line, before the PSTN destination answers.
// They therefore cannot safely compete with parallel legs or their own inbound
// port without prematurely winning and stranding the source call.
func unsafeExternalAdvancedStage(plan store.AdvancedRoute, stage store.RouteStage) string {
	enabled := 0
	external := 0
	for _, target := range stage.Targets {
		if !target.Enabled || strings.TrimSpace(target.Value) == "" {
			continue
		}
		enabled++
		if target.Kind == "external" {
			external++
			if plan.IngressKind == "gateway" && strings.TrimSpace(target.Trunk) == strings.TrimSpace(plan.IngressValue) {
				return "outbound gateway matches inbound gateway"
			}
		}
	}
	if external == 0 {
		return ""
	}
	if external != 1 || enabled != 1 {
		return "outside-number forwarding must be the only active target"
	}
	if mode := strings.TrimSpace(stage.AnswerMode); mode != "" && mode != "first_answer" {
		return "outside-number forwarding requires first_answer mode"
	}
	return ""
}

func advancedRouteTargetKey(target store.RouteTarget) string {
	if target.Kind == "sip" || target.Kind == "gateway" {
		return "endpoint:" + target.Value
	}
	return target.Kind + ":" + target.Value + ":" + target.Trunk
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
		s.log.Warn("advanced route destination has no registered SIP contact", map[string]any{
			"call_id": run.parentID, "route_id": run.plan.ID,
			"kind": target.Kind, "target": target.Value,
		})
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
	s.log.Info("advanced route SIP destination ringing", map[string]any{
		"call_id": run.parentID, "route_id": run.plan.ID,
		"leg_id": legID, "kind": target.Kind, "target": target.Value,
		"timeout_seconds": timeout,
	})
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

func (s *Server) activateAdvancedRoute(run *advancedRouteRun, winner, answeredBy string, maxCallSeconds int) {
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
	if maxCallSeconds > 0 {
		go s.enforceAdvancedRouteCallLimit(run, time.Duration(maxCallSeconds)*time.Second)
	}
}

func (s *Server) enforceAdvancedRouteCallLimit(run *advancedRouteRun, limit time.Duration) {
	if run == nil || limit <= 0 {
		return
	}
	timer := time.NewTimer(limit)
	defer timer.Stop()
	select {
	case <-run.done:
		return
	case <-timer.C:
		s.log.Info("advanced route connected-call limit reached", map[string]any{
			"call_id": run.parentID, "route_id": run.plan.ID, "limit_seconds": int(limit.Seconds()),
		})
		s.endAdvancedRoute(run, "call_time_limit", true)
	}
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

// declineAdvancedRouteNode removes one HAOS destination from an in-flight
// route. It returns handled=true for advanced calls and keepRouting=true when
// another HAOS or SIP destination can still answer. The source bridge is only
// terminated when the declining card was the final destination.
func (s *Server) declineAdvancedRouteNode(callID, nodeID string) (run *advancedRouteRun, keepRouting, handled bool) {
	s.advancedRoutesMu.Lock()
	run = s.advancedRoutes[callID]
	s.advancedRoutesMu.Unlock()
	if run == nil {
		return nil, false, false
	}

	run.mu.Lock()
	if run.closed || !run.invitedNodes[nodeID] {
		run.mu.Unlock()
		return run, false, true
	}
	delete(run.invitedNodes, nodeID)
	keepRouting = len(run.invitedNodes) > 0 || len(run.children) > 0
	run.mu.Unlock()
	return run, keepRouting, true
}

func (s *Server) advancedRouteForCall(callID string) *advancedRouteRun {
	s.advancedRoutesMu.Lock()
	defer s.advancedRoutesMu.Unlock()
	return s.advancedRoutes[callID]
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
	if run.done != nil {
		close(run.done)
	}
	children := make([]string, 0, len(run.children))
	for id := range run.children {
		children = append(children, id)
	}
	run.mu.Unlock()
	if call, ok := s.calls.End(run.parentID, reason); ok {
		s.notifyCallStatus(call)
	}
	for _, id := range children {
		if s.asterisk != nil {
			_ = s.asterisk.HangupCall(id)
		}
		s.removeAdvancedRouteLeg(id)
	}
	if hangupBridge && s.asterisk != nil {
		_ = s.asterisk.HangupCall(run.parentID)
		if run.bridgeID != "" {
			_ = s.asterisk.HangupBridge(run.bridgeID, "")
		}
	}
	if s.asterisk != nil {
		s.asterisk.UntrackCall(run.parentID)
	}
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
