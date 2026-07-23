package server

import (
	"fmt"
	"strings"
	"time"

	"github.com/nitish-mp3/simson-vps/asterisk"
	"github.com/nitish-mp3/simson-vps/calls"
)

const gatewayTransferInterdigitTimeout = 1200 * time.Millisecond

type gatewayBridgeFeatureAction string

const (
	gatewayBridgeTransfer   gatewayBridgeFeatureAction = "transfer"
	gatewayBridgeConference gatewayBridgeFeatureAction = "conference"
)

type gatewayBridgeFeatureCode struct {
	Code   string
	Action gatewayBridgeFeatureAction
}

type gatewayTransferCapture struct {
	CallID     string
	AccountID  string
	Channel    string
	SourceExt  string
	Codes      []gatewayBridgeFeatureCode
	Action     gatewayBridgeFeatureAction
	Sequence   string
	Target     string
	Generation uint64
}

type gatewayTransferPending struct {
	CallID        string
	AccountID     string
	SourceExt     string
	SourceChannel string
	TargetExt     string
	Action        gatewayBridgeFeatureAction
}

type gatewayTransferDTMFStamp struct {
	Digit string
	At    time.Time
}

func normalizeTransferCode(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if !strings.HasPrefix(value, "*") {
		value = "*" + value
	}
	if len(value) < 2 || len(value) > 8 {
		return ""
	}
	for _, r := range value[1:] {
		if r < '0' || r > '9' {
			return ""
		}
	}
	return value
}

// advanceGatewayTransferCapture consumes one DTMF digit. It deliberately does
// not treat a partial code or destination as a transfer, so ordinary DTMF and
// malformed feature codes cannot tear down a working gateway call.
func advanceGatewayTransferCapture(c *gatewayTransferCapture, digit string) (target string, completed bool, keep bool) {
	if c == nil || len(digit) != 1 || len(c.Codes) == 0 {
		return "", false, false
	}
	if c.Action == "" {
		next := c.Sequence + digit
		matchedPrefix := false
		for _, feature := range c.Codes {
			if strings.HasPrefix(feature.Code, next) {
				matchedPrefix = true
			}
			if feature.Code == next {
				c.Action = feature.Action
			}
		}
		if !matchedPrefix {
			return "", false, false
		}
		c.Sequence = next
		return "", false, true
	}
	if digit == "#" {
		return c.Target, c.Target != "", false
	}
	if digit < "0" || digit > "9" || len(c.Target) >= 20 {
		return "", false, false
	}
	c.Target += digit
	return "", false, true
}

func configuredGatewayBridgeFeatureCodes(transferCode, conferenceCode string) []gatewayBridgeFeatureCode {
	transferCode = normalizeTransferCode(transferCode)
	conferenceCode = normalizeTransferCode(conferenceCode)
	codes := make([]gatewayBridgeFeatureCode, 0, 2)
	if transferCode != "" {
		codes = append(codes, gatewayBridgeFeatureCode{Code: transferCode, Action: gatewayBridgeTransfer})
	}
	// Ambiguous duplicate codes are resolved as transfer, the safer operation
	// because it preserves the account's existing *84 behavior.
	if conferenceCode != "" && conferenceCode != transferCode {
		codes = append(codes, gatewayBridgeFeatureCode{Code: conferenceCode, Action: gatewayBridgeConference})
	}
	return codes
}

func gatewayFeatureStartsWith(codes []gatewayBridgeFeatureCode, digit string) bool {
	for _, feature := range codes {
		if strings.HasPrefix(feature.Code, digit) {
			return true
		}
	}
	return false
}

// enqueueGatewayBridgeDTMF is called on the AMI reader goroutine. Never do
// database or AMI work here; preserving event order is more important than
// spawning one goroutine per digit.
func (s *Server) enqueueGatewayBridgeDTMF(info asterisk.ChannelDTMF) {
	select {
	case s.gatewayTransferDTMFQueue <- info:
	default:
		s.log.Warn("gateway transfer DTMF queue full; digit discarded", map[string]any{
			"channel": info.Channel,
		})
	}
}

func (s *Server) runGatewayBridgeDTMFQueue() {
	for info := range s.gatewayTransferDTMFQueue {
		s.handleGatewayBridgeDTMF(info)
	}
}

func (s *Server) handleGatewayBridgeDTMF(info asterisk.ChannelDTMF) {
	if s.asterisk == nil || info.Channel == "" || len(info.Digit) != 1 {
		return
	}
	sourceExt := extractEndpointFromChannel(info.Channel)
	if sourceExt == "" {
		return
	}
	sourceEP, err := s.store.GetSIPEndpointByExtension(sourceExt)
	if err != nil || sourceEP == nil || !sourceEP.Enabled {
		return
	}

	callID, mapped := s.asterisk.CallIDForChannel(info.Channel)
	call := s.calls.Get(callID)
	managedBridge := mapped && call != nil && call.State == calls.StateActive && s.isSIPBridgeFeatureCall(call)
	accountID := sourceEP.AccountID
	if managedBridge {
		if sourceEP.AccountID != call.AccountID {
			return
		}
		accountID = call.AccountID
	} else {
		// Direct SIP calls are not represented by a Simson call/bridge. They
		// may use only the conference code; *84 remains Asterisk's native
		// transfer path and must not be duplicated here.
		callID = ""
	}

	features, err := s.store.GetAccountCallFeatures(accountID)
	if err != nil || features == nil || !features.Enabled {
		return
	}
	codes := configuredGatewayBridgeFeatureCodes(features.TransferCode, features.ConferenceCode)
	if !managedBridge {
		codes = configuredGatewayBridgeFeatureCodes("", features.ConferenceCode)
	}
	if len(codes) == 0 {
		return
	}

	now := time.Now()
	s.gatewayTransferMu.Lock()
	if last := s.gatewayTransferLastDTMF[info.Channel]; last.Digit == info.Digit && now.Sub(last.At) < 80*time.Millisecond {
		s.gatewayTransferMu.Unlock()
		return
	}
	s.gatewayTransferLastDTMF[info.Channel] = gatewayTransferDTMFStamp{Digit: info.Digit, At: now}
	if _, pending := s.gatewayTransferPending[callID]; pending {
		s.gatewayTransferMu.Unlock()
		return
	}
	capture := s.gatewayTransferCaptures[info.Channel]
	if capture == nil {
		if !gatewayFeatureStartsWith(codes, info.Digit) {
			s.gatewayTransferMu.Unlock()
			return
		}
		capture = &gatewayTransferCapture{
			CallID: callID, AccountID: accountID, Channel: info.Channel,
			SourceExt: sourceExt, Codes: codes,
		}
		s.gatewayTransferCaptures[info.Channel] = capture
	}
	target, complete, keep := advanceGatewayTransferCapture(capture, info.Digit)
	if !keep {
		delete(s.gatewayTransferCaptures, info.Channel)
		// A fresh leading star restarts a malformed/incomplete sequence. This
		// makes a handset retry deterministic without forwarding stale digits.
		if gatewayFeatureStartsWith(codes, info.Digit) {
			capture = &gatewayTransferCapture{
				CallID: callID, AccountID: accountID, Channel: info.Channel,
				SourceExt: sourceExt, Codes: codes,
			}
			_, _, keep = advanceGatewayTransferCapture(capture, info.Digit)
			s.gatewayTransferCaptures[info.Channel] = capture
		}
	}
	if keep && capture.Action != "" && capture.Target != "" {
		capture.Generation++
		generation := capture.Generation
		channel := capture.Channel
		go func() {
			time.Sleep(gatewayTransferInterdigitTimeout)
			s.finishGatewayTransferCapture(channel, generation)
		}()
	}
	candidate, action := capture.Target, capture.Action
	s.gatewayTransferMu.Unlock()

	if complete {
		s.startGatewayBridgeFeature(action, callID, info.Channel, sourceExt, target)
		return
	}
	// Exact, unambiguous onsite extensions can transfer immediately without an
	// artificial timeout. Variable-length or outside destinations still use #
	// (or the short inter-digit timeout) to determine completion.
	if keep && candidate != "" && s.isUnambiguousGatewayTransferTarget(accountID, candidate) {
		s.gatewayTransferMu.Lock()
		if current := s.gatewayTransferCaptures[info.Channel]; current == capture {
			delete(s.gatewayTransferCaptures, info.Channel)
			target = candidate
		}
		s.gatewayTransferMu.Unlock()
		if target != "" {
			s.startGatewayBridgeFeature(action, callID, info.Channel, sourceExt, target)
		}
	}
}

func (s *Server) finishGatewayTransferCapture(channel string, generation uint64) {
	s.gatewayTransferMu.Lock()
	capture := s.gatewayTransferCaptures[channel]
	if capture == nil || capture.Generation != generation || capture.Target == "" {
		s.gatewayTransferMu.Unlock()
		return
	}
	delete(s.gatewayTransferCaptures, channel)
	callID, sourceExt, target, action := capture.CallID, capture.SourceExt, capture.Target, capture.Action
	s.gatewayTransferMu.Unlock()
	s.startGatewayBridgeFeature(action, callID, channel, sourceExt, target)
}

func (s *Server) isUnambiguousGatewayTransferTarget(accountID, target string) bool {
	endpoints, err := s.store.ListSIPEndpoints(accountID)
	if err != nil {
		return false
	}
	exact := false
	for _, ep := range endpoints {
		ext := strings.TrimSpace(ep.Extension)
		if !ep.Enabled || isReservedGatewayExtension(ext) {
			continue
		}
		if ext == target {
			exact = true
			continue
		}
		if strings.HasPrefix(ext, target) {
			return false
		}
	}
	return exact
}

func (s *Server) startGatewayBridgeFeature(action gatewayBridgeFeatureAction, callID, sourceChannel, sourceExt, target string) {
	if callID == "" {
		if action == gatewayBridgeConference {
			s.startDirectSIPConference(sourceChannel, sourceExt, target)
		}
		return
	}
	call := s.calls.Get(callID)
	if call == nil || call.State != calls.StateActive || !s.isSIPBridgeFeatureCall(call) {
		return
	}
	target = strings.TrimSpace(target)
	targetEP, err := s.store.GetSIPEndpointByExtension(target)
	if err != nil || targetEP == nil || !targetEP.Enabled || targetEP.AccountID != call.AccountID || isReservedGatewayExtension(target) || target == sourceExt {
		s.log.Warn("gateway bridge transfer rejected", map[string]any{
			"call_id": callID, "source": sourceExt, "target": target, "reason": "target is not an enabled same-site SIP phone",
		})
		return
	}

	pending := &gatewayTransferPending{
		CallID: callID, AccountID: call.AccountID, SourceExt: sourceExt,
		SourceChannel: sourceChannel, TargetExt: target, Action: action,
	}
	s.gatewayTransferMu.Lock()
	if _, exists := s.gatewayTransferPending[callID]; exists {
		s.gatewayTransferMu.Unlock()
		return
	}
	s.gatewayTransferPending[callID] = pending
	s.gatewayTransferMu.Unlock()

	callerNumber := digitsOnly(strings.TrimPrefix(call.ToNode, "sip:"))
	callerID := formatSIPCallerID("Transferred outside call", callerNumber)
	if action == gatewayBridgeConference {
		_, err = s.asterisk.OriginateBridgeConference(
			target, s.cfg.Asterisk.NodeContext, call.SIPBridgeID, callerID,
			callID, call.FromNode, sourceChannel, sourceExt, s.cfg.CallTimeoutSec,
		)
	} else {
		action = gatewayBridgeTransfer
		pending.Action = action
		_, err = s.asterisk.OriginateBridgeTransfer(
			target, s.cfg.Asterisk.NodeContext, call.SIPBridgeID, callerID,
			callID, call.FromNode, sourceChannel, sourceExt, s.cfg.CallTimeoutSec,
		)
	}
	if err != nil {
		s.gatewayTransferMu.Lock()
		delete(s.gatewayTransferPending, callID)
		s.gatewayTransferMu.Unlock()
		s.log.Warn("gateway bridge transfer originate failed", map[string]any{
			"call_id": callID, "source": sourceExt, "target": target, "err": err.Error(),
		})
		return
	}
	s.log.Info("gateway bridge feature target ringing", map[string]any{
		"call_id": callID, "source": sourceExt, "target": target,
		"action": action, "bridge": call.SIPBridgeID,
	})
}

func (s *Server) startDirectSIPConference(sourceChannel, sourceExt, target string) {
	sourceEP, err := s.store.GetSIPEndpointByExtension(sourceExt)
	if err != nil || sourceEP == nil || !sourceEP.Enabled {
		return
	}
	target = strings.TrimSpace(target)
	targetEP, err := s.store.GetSIPEndpointByExtension(target)
	if err != nil || targetEP == nil || !targetEP.Enabled || targetEP.AccountID != sourceEP.AccountID ||
		isReservedGatewayExtension(target) || target == sourceExt {
		s.log.Warn("direct SIP conference rejected", map[string]any{
			"source": sourceExt, "target": target, "reason": "target is not an enabled same-site SIP phone",
		})
		return
	}
	callerID := formatSIPCallerID("Conference", sourceExt)
	if _, err := s.asterisk.OriginateDirectConference(target, sourceChannel, callerID, s.cfg.CallTimeoutSec); err != nil {
		s.log.Warn("direct SIP conference originate failed", map[string]any{
			"source": sourceExt, "target": target, "channel": sourceChannel, "err": err.Error(),
		})
		return
	}
	s.store.WriteAudit(sourceEP.AccountID, "sip:"+sourceExt, "direct_sip_conference",
		fmt.Sprintf("source=%s added=%s channel=%s", sourceExt, target, sourceChannel), "")
	s.log.Info("direct SIP conference participant ringing", map[string]any{
		"source": sourceExt, "target": target, "channel": sourceChannel,
	})
}

func (s *Server) handleGatewayBridgeTransferResult(result asterisk.BridgeTransferResult) {
	s.gatewayTransferMu.Lock()
	pending := s.gatewayTransferPending[result.CallID]
	matched := pending != nil && pending.SourceChannel == result.SourceChannel && pending.TargetExt == result.TargetExt &&
		result.ReplaceSource == (pending.Action == gatewayBridgeTransfer)
	if matched {
		delete(s.gatewayTransferPending, result.CallID)
		if !result.OK {
			s.gatewayTransferFailedTargets[result.CallID+"|"+result.TargetExt] = time.Now().Add(5 * time.Second)
		}
	}
	s.gatewayTransferMu.Unlock()
	if !matched {
		// A late response must not create an orphan target leg after the parent
		// call ended or a newer transfer superseded this request.
		if result.OK && result.Channel != "" {
			_ = s.asterisk.HangupChannel(result.Channel)
		}
		return
	}
	if !result.OK {
		s.log.Warn("gateway bridge feature target did not answer; original call retained", map[string]any{
			"call_id": result.CallID, "source": result.SourceExt, "target": result.TargetExt,
			"action": pending.Action, "reason": result.Reason,
		})
		return
	}
	call := s.calls.Get(result.CallID)
	if call == nil || call.State != calls.StateActive || !s.isSIPBridgeFeatureCall(call) {
		if result.Channel != "" {
			_ = s.asterisk.HangupChannel(result.Channel)
		}
		s.log.Info("discarded stale gateway bridge transfer answer", map[string]any{
			"call_id": result.CallID, "source": result.SourceExt, "target": result.TargetExt,
		})
		return
	}
	if pending.Action == gatewayBridgeConference {
		s.store.WriteAudit(pending.AccountID, "sip:"+result.SourceExt, "gateway_bridge_conference",
			fmt.Sprintf("call=%s source=%s added=%s", result.CallID, result.SourceExt, result.TargetExt), "")
		s.log.Info("gateway bridge conference participant added", map[string]any{
			"call_id": result.CallID, "source": result.SourceExt, "target": result.TargetExt,
		})
		return
	}
	s.gatewayTransferMu.Lock()
	s.gatewayTransferReleased[result.SourceChannel] = time.Now().Add(30 * time.Second)
	s.gatewayTransferMu.Unlock()
	if err := s.asterisk.HangupChannel(result.SourceChannel); err != nil && !strings.Contains(strings.ToLower(err.Error()), "no such channel") {
		s.log.Warn("gateway bridge transfer connected but source release failed", map[string]any{
			"call_id": result.CallID, "source": result.SourceExt, "target": result.TargetExt, "err": err.Error(),
		})
		return
	}
	s.store.WriteAudit(pending.AccountID, "sip:"+result.SourceExt, "gateway_bridge_transfer",
		fmt.Sprintf("call=%s source=%s target=%s", result.CallID, result.SourceExt, result.TargetExt), "")
	s.log.Info("gateway bridge transfer completed", map[string]any{
		"call_id": result.CallID, "source": result.SourceExt, "target": result.TargetExt,
	})
}

func (s *Server) shouldIgnoreGatewayTransferHangup(callID, channel string) bool {
	now := time.Now()
	endpoint := extractEndpointFromChannel(channel)
	s.gatewayTransferMu.Lock()
	defer s.gatewayTransferMu.Unlock()
	for ch, until := range s.gatewayTransferReleased {
		if now.After(until) {
			delete(s.gatewayTransferReleased, ch)
		}
	}
	for key, until := range s.gatewayTransferFailedTargets {
		if now.After(until) {
			delete(s.gatewayTransferFailedTargets, key)
		}
	}
	if until, ok := s.gatewayTransferReleased[channel]; ok && now.Before(until) {
		delete(s.gatewayTransferReleased, channel)
		return true
	}
	if pending := s.gatewayTransferPending[callID]; pending != nil && endpoint == pending.TargetExt {
		return true
	}
	if until, ok := s.gatewayTransferFailedTargets[callID+"|"+endpoint]; ok && now.Before(until) {
		return true
	}
	return false
}
