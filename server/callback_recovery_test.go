package server

import (
	"strings"
	"testing"
	"time"

	"github.com/nitish-mp3/simson-vps/calls"
)

func TestCallbackWatchdogKeepsHealthyCallsAndRecoversMissingPeer(t *testing.T) {
	now := time.Now()
	call := &calls.Call{State: calls.StateActive}
	callback := &sipGatewayCallback{Stage: "gateway", RingDeadline: now.Add(-time.Hour)}
	if reason := callbackRecoveryReason(call, callback, 2, now); reason != "" {
		t.Fatalf("healthy call was expired: %s", reason)
	}
	if reason := callbackRecoveryReason(call, callback, 1, now); reason != "" {
		t.Fatal("missing peer must have a grace period")
	}
	if reason := callbackRecoveryReason(call, callback, 1, now.Add(19*time.Second)); reason != "" {
		t.Fatal("peer recovery ended the call prematurely")
	}
	if reason := callbackRecoveryReason(call, callback, 1, now.Add(20*time.Second)); reason != "callback_peer_missing" {
		t.Fatalf("orphan call was not recovered: %s", reason)
	}
	callbackRecoveryReason(call, callback, 2, now.Add(21*time.Second))
	if !callback.PeerMissingSince.IsZero() {
		t.Fatal("restored peer did not reset the watchdog")
	}
	call.State = calls.StateRinging
	if reason := callbackRecoveryReason(call, callback, 1, now); reason != "timeout" {
		t.Fatalf("ring deadline ignored: %s", reason)
	}
}

func TestCallbackParticipantCountExcludesAnnouncementsAndOtherRooms(t *testing.T) {
	output := strings.Join([]string{
		"Local/3101@from-simson-callback-source-0001;1!from-simson-node!bridge-one!4!Up!ConfBridge!bridge-one,simson_bridge,simson_user",
		"Local/0912@from-simson-out-0002;1!from-simson-node!bridge-one!4!Up!ConfBridge!bridge-one,simson_bridge,simson_user",
		"CBAnn/bridge-one-0001;1!default!s!1!Up!ConfBridge!bridge-one",
		"PJSIP/9999-0003!from-simson-node!bridge-other!4!Up!ConfBridge!bridge-other",
	}, "\n")
	count, source := callbackBridgeParticipants(output, "bridge-one")
	if count != 2 || !source {
		t.Fatalf("participants=%d source=%v", count, source)
	}
}

func TestCallbackTelemetryIsSiteScopedAndCompatibleWithOlderAddons(t *testing.T) {
	call := &calls.Call{ControlNodeID: "office", AccountID: "site-a"}
	for _, version := range []string{"5.1.8", "5.2.0", "6.0.0"} {
		if !canSendCallbackTelemetry(call, "office", "site-a", version) {
			t.Fatalf("compatible addon %s rejected", version)
		}
	}
	for _, version := range []string{"", "invalid", "5.1.7", "5.0.9", "4.9.9"} {
		if canSendCallbackTelemetry(call, "office", "site-a", version) {
			t.Fatalf("old addon %s would expose callback telemetry", version)
		}
	}
	if canSendCallbackTelemetry(call, "other-node", "site-a", "5.1.8") || canSendCallbackTelemetry(call, "office", "site-b", "5.1.8") {
		t.Fatal("callback telemetry escaped its owner node/account")
	}
}
