package server

import (
	"strings"
	"time"

	"github.com/nitish-mp3/simson-vps/calls"
)

func activeOutboundLocalHangup(call *calls.Call, channel, primary, context string) bool {
	if call == nil || call.State != calls.StateActive || call.CallType != "sip" || call.SIPBridgeID == "" || channel != primary {
		return false
	}
	if call.GatewayTrunk == "" && !isExternalDialString(strings.TrimPrefix(call.ToNode, "sip:")) {
		return false
	}
	if context == "" {
		context = "from-simson-out"
	}
	separator := strings.LastIndex(channel, "-")
	address := strings.LastIndex(channel, "@")
	return strings.HasPrefix(channel, "Local/") && address > 0 && separator > address && channel[address+1:separator] == context
}

func validGatewaySnapshot(output string) bool {
	complete := false
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "--END COMMAND--" {
			complete = true
			continue
		}
		if line != "" && len(strings.Split(line, "!")) < 14 {
			return false
		}
	}
	return complete
}

func gatewayPeerHealthy(output string, channels []string, trunk string, participants int) bool {
	if participants < 2 {
		return false
	}
	if trunk == "" {
		return true
	}
	owned := make(map[string]bool, len(channels))
	for _, channel := range channels {
		owned[channel] = true
	}
	for _, line := range strings.Split(output, "\n") {
		parts := strings.Split(strings.TrimSpace(line), "!")
		if len(parts) >= 5 && owned[parts[0]] && strings.HasPrefix(parts[0], "PJSIP/"+trunk+"-") && strings.EqualFold(parts[4], "Up") {
			return true
		}
	}
	return false
}

func gatewayRecoveryReason(call *calls.Call, callback *sipGatewayCallback, healthy bool, missingSince *time.Time, now time.Time, grace time.Duration) string {
	if call == nil {
		return ""
	}
	if call.State == calls.StateRinging && callback != nil && !callback.RingDeadline.IsZero() && !now.Before(callback.RingDeadline) {
		return "timeout"
	}
	if call.State != calls.StateActive || healthy || callback != nil && callback.Stage != "gateway" {
		*missingSince = time.Time{}
		return ""
	}
	if missingSince.IsZero() || now.Before(*missingSince) {
		*missingSince = now
		return ""
	}
	if now.Sub(*missingSince) >= grace {
		return "gateway_peer_missing"
	}
	return ""
}

func (s *Server) resetGatewayPeerObservations() {
	s.sipGatewayCallbackMu.Lock()
	s.sipGatewayPeerMissing = nil
	s.sipGatewayCallbackMu.Unlock()
}

func (s *Server) releaseEndedSIPOriginate(callID string) {
	if s.asterisk == nil {
		return
	}
	for _, call := range s.calls.Snapshots() {
		if call.ID != callID || call.State != calls.StateEnded && call.State != calls.StateFailed {
			continue
		}
		if err := s.asterisk.HangupCall(callID); err != nil {
			s.log.Warn("late answered SIP leg cleanup needs reconciliation", map[string]any{"call_id": callID, "err": err.Error()})
			return
		}
		if err := s.asterisk.HangupBridge(call.SIPBridgeID, ""); err != nil {
			s.log.Warn("late answered SIP bridge cleanup needs reconciliation", map[string]any{"call_id": callID, "err": err.Error()})
			return
		}
		s.asterisk.UntrackCall(callID)
		return
	}
}
