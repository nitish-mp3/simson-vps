package server

import (
	"strings"
	"time"
)

type gatewayFailure struct {
	Cause string
	At    time.Time
}

func gatewayFailureReason(cause string) string {
	switch strings.TrimSpace(cause) {
	case "17":
		return "gateway_busy"
	case "21":
		return "gateway_rejected"
	default:
		return ""
	}
}

func (s *Server) recordGatewayFailure(callID, cause string) {
	s.gatewayHangupFallbackMu.Lock()
	defer s.gatewayHangupFallbackMu.Unlock()
	now := time.Now()
	if s.gatewayFailures == nil {
		s.gatewayFailures = make(map[string]gatewayFailure)
	}
	for key, failure := range s.gatewayFailures {
		if now.Sub(failure.At) > time.Minute || len(s.gatewayFailures) >= 256 {
			delete(s.gatewayFailures, key)
		}
	}
	s.gatewayFailures[callID] = gatewayFailure{Cause: cause, At: now}
}

func (s *Server) consumeGatewayFailure(callID string) string {
	s.gatewayHangupFallbackMu.Lock()
	defer s.gatewayHangupFallbackMu.Unlock()
	failure, found := s.gatewayFailures[callID]
	delete(s.gatewayFailures, callID)
	if !found || time.Since(failure.At) > time.Minute {
		return ""
	}
	return gatewayFailureReason(failure.Cause)
}
