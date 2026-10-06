package server

import (
	"testing"
	"time"

	"github.com/nitish-mp3/simson-vps/calls"
)

func TestGatewayFailurePreservesCauseAndNeverRetriesBusy(t *testing.T) {
	server := &Server{}
	server.recordGatewayFailure("call-one", "17")
	server.recordGatewayFailure("call-two", "21")
	for callID, expected := range map[string]string{"call-one": "gateway_busy", "call-two": "gateway_rejected"} {
		reason := server.consumeGatewayFailure(callID)
		if reason != expected || gatewayOriginateRetryAllowed(reason) {
			t.Fatalf("%s incorrectly classified/retried: %s", callID, reason)
		}
		if server.consumeGatewayFailure(callID) != "" {
			t.Fatal("cause consumed twice")
		}
		manager := calls.NewManager()
		manager.Create(&calls.Call{ID: callID})
		call, ended := manager.End(callID, reason)
		if !ended || call.State != calls.StateFailed {
			t.Fatal("gateway rejection must be reported as failed")
		}
	}
	server.gatewayFailures["expired"] = gatewayFailure{Cause: "17", At: time.Now().Add(-2 * time.Minute)}
	if server.consumeGatewayFailure("expired") != "" || gatewayFailureReason("16") != "" {
		t.Fatal("stale/normal hangup treated as current gateway failure")
	}
	for index := 0; index < 400; index++ {
		server.recordGatewayFailure(string(rune(index)), "17")
	}
	if len(server.gatewayFailures) > 256 {
		t.Fatal("failure cache is unbounded")
	}
}
