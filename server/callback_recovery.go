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

func (s *Server) reconcileOutboundGatewayCalls() {
	if s.asterisk == nil || !s.asterisk.Connected() {
		s.resetGatewayPeerObservations()
		return
	}
	output, err := s.asterisk.RunCommand("core show channels concise")
	if err != nil {
		s.resetGatewayPeerObservations()
		s.log.Warn("gateway reconciliation could not inspect Asterisk", map[string]any{"err": err.Error()})
		return
	}
	if !validGatewaySnapshot(output) {
		s.resetGatewayPeerObservations()
		s.log.Warn("gateway reconciliation skipped an incomplete channel snapshot", nil)
		return
	}
	grace := 20 * time.Second
	if s.cfg != nil && s.cfg.Asterisk.GatewayPeerGraceSec >= 5 {
		grace = time.Duration(s.cfg.Asterisk.GatewayPeerGraceSec) * time.Second
	}
	observed := make(map[string]bool)
	for _, call := range s.calls.Snapshots() {
		if call.CallType != "sip" || call.SIPBridgeID == "" {
			continue
		}
		participants, _ := callbackBridgeParticipants(output, call.SIPBridgeID)
		s.sipGatewayCallbackMu.Lock()
		var callback *sipGatewayCallback
		if current := s.sipGatewayCallbacks[call.ID]; current != nil {
			copy := *current
			callback = &copy
		}
		s.sipGatewayCallbackMu.Unlock()
		if callback == nil && call.GatewayTrunk == "" && !s.isOutboundGatewayCall(call) {
			continue
		}
		s.gatewayTransferMu.Lock()
		transferring := s.gatewayTransferPending[call.ID] != nil
		s.gatewayTransferMu.Unlock()
		if transferring {
			continue
		}
		channels := s.asterisk.CallChannelsFromSnapshot(output, call.ID, call.SIPBridgeID)
		healthy := gatewayPeerHealthy(output, channels, call.GatewayTrunk, participants)
		s.sipGatewayCallbackMu.Lock()
		if s.sipGatewayPeerMissing == nil {
			s.sipGatewayPeerMissing = make(map[string]time.Time)
		}
		missingSince := s.sipGatewayPeerMissing[call.ID]
		reason := gatewayRecoveryReason(call, callback, healthy, &missingSince, time.Now(), grace)
		s.sipGatewayPeerMissing[call.ID] = missingSince
		s.sipGatewayCallbackMu.Unlock()
		observed[call.ID] = call.State == calls.StateActive
		terminal := call.State == calls.StateEnded || call.State == calls.StateFailed
		if reason == "" && !(terminal && len(channels) > 0) {
			continue
		}
		if reason != "" {
			ended, changed := s.calls.EndIfState(call.ID, call.State, reason)
			if !changed {
				continue
			}
			s.notifyCallStatus(ended)
			s.finishSIPIntercomCallback(call.ID, "", false)
			s.releaseSIPBridgeTransferForCall(ended)
		}
		s.clearSIPOutboundRetry(call.ID)
		s.sipGatewayCallbackMu.Lock()
		delete(s.sipGatewayCallbacks, call.ID)
		s.sipGatewayCallbackMu.Unlock()
		if err := s.asterisk.HangupCall(call.ID); err != nil {
			s.log.Warn("gateway reconciliation cleanup failed", map[string]any{"call_id": call.ID, "err": err.Error()})
			continue
		}
		if err := s.asterisk.HangupBridge(call.SIPBridgeID, ""); err != nil {
			s.log.Warn("gateway reconciliation bridge cleanup failed", map[string]any{"call_id": call.ID, "err": err.Error()})
			continue
		}
		s.asterisk.UntrackCall(call.ID)
		s.log.Info("gateway call channels automatically released", map[string]any{"call_id": call.ID, "reason": reason})
	}
	s.sipGatewayCallbackMu.Lock()
	for callID := range s.sipGatewayPeerMissing {
		if !observed[callID] {
			delete(s.sipGatewayPeerMissing, callID)
		}
	}
	s.sipGatewayCallbackMu.Unlock()
}
