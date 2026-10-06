package server

import (
	"strconv"
	"strings"
	"time"

	"github.com/nitish-mp3/simson-vps/calls"
)

func canSendCallbackTelemetry(call *calls.Call, nodeID, accountID, version string) bool {
	if call == nil || call.ControlNodeID != nodeID || call.AccountID != accountID {
		return false
	}
	parts := strings.Split(version, ".")
	if len(parts) != 3 {
		return false
	}
	values := make([]int, 3)
	for index, part := range parts {
		value, err := strconv.Atoi(part)
		if err != nil || value < 0 {
			return false
		}
		values[index] = value
	}
	return values[0] > 5 || values[0] == 5 && (values[1] > 1 || values[1] == 1 && values[2] >= 8)
}

func callbackRecoveryReason(call *calls.Call, callback *sipGatewayCallback, participants int, now time.Time) string {
	if call == nil || callback == nil {
		return ""
	}
	if call.State == calls.StateRinging && !callback.RingDeadline.IsZero() && !now.Before(callback.RingDeadline) {
		return "timeout"
	}
	if call.State != calls.StateActive || callback.Stage != "gateway" {
		return ""
	}
	if participants >= 2 {
		callback.PeerMissingSince = time.Time{}
		return ""
	}
	if callback.PeerMissingSince.IsZero() {
		callback.PeerMissingSince = now
		return ""
	}
	if now.Sub(callback.PeerMissingSince) >= 20*time.Second {
		return "callback_peer_missing"
	}
	return ""
}

func callbackBridgeParticipants(output, bridgeID string) (int, bool) {
	participants := 0
	callbackSource := false
	for _, line := range strings.Split(output, "\n") {
		parts := strings.Split(strings.TrimSpace(line), "!")
		if len(parts) < 7 || parts[5] != "ConfBridge" || strings.Split(parts[6], ",")[0] != bridgeID {
			continue
		}
		if strings.HasPrefix(parts[0], "CBAnn/") {
			continue
		}
		participants++
		if strings.HasPrefix(parts[0], "Local/") && strings.Contains(parts[0], "@from-simson-callback-source-") {
			callbackSource = true
		}
	}
	return participants, callbackSource
}

func (s *Server) reconcileSIPGatewayCallbacks() {
	if s.asterisk == nil || !s.asterisk.Connected() {
		return
	}
	output, err := s.asterisk.RunCommand("core show channels concise")
	if err != nil {
		s.log.Warn("callback reconciliation could not inspect Asterisk", map[string]any{"err": err.Error()})
		return
	}
	for _, call := range s.calls.Snapshots() {
		if call.CallType != "sip" || call.SIPBridgeID == "" {
			continue
		}
		participants, hasSource := callbackBridgeParticipants(output, call.SIPBridgeID)
		s.sipGatewayCallbackMu.Lock()
		callback := s.sipGatewayCallbacks[call.ID]
		reason := callbackRecoveryReason(call, callback, participants, time.Now())
		s.sipGatewayCallbackMu.Unlock()
		terminal := call.State == calls.StateEnded || call.State == calls.StateFailed
		if reason == "" && !(terminal && hasSource) {
			continue
		}
		if reason != "" {
			ended, changed := s.calls.EndIfState(call.ID, call.State, reason)
			if !changed {
				continue
			}
			s.notifyCallStatus(ended)
		}
		s.clearSIPOutboundRetry(call.ID)
		s.sipGatewayCallbackMu.Lock()
		delete(s.sipGatewayCallbacks, call.ID)
		s.sipGatewayCallbackMu.Unlock()
		if err := s.asterisk.HangupCall(call.ID); err != nil {
			s.log.Warn("callback reconciliation cleanup failed", map[string]any{"call_id": call.ID, "err": err.Error()})
			continue
		}
		s.asterisk.UntrackCall(call.ID)
		s.log.Info("callback channels automatically released", map[string]any{"call_id": call.ID, "reason": reason})
	}
}
