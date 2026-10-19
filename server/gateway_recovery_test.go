package server

import (
	"strings"
	"testing"
	"time"

	"github.com/nitish-mp3/simson-vps/calls"
)

func TestAnsweredOutboundLocalHangupIsFinalOnlyForCurrentGatewayLeg(t *testing.T) {
	call := &calls.Call{State: calls.StateActive, CallType: "sip", SIPBridgeID: "bridge-one", ToNode: "sip:9123208334", GatewayTrunk: "1701"}
	channel := "Local/09123208334@from-simson-out-00000001"
	if !activeOutboundLocalHangup(call, channel, channel, "from-simson-out") {
		t.Fatal("answered gateway Local leg was ignored")
	}
	for _, state := range []calls.State{calls.StateRinging, calls.StateEnded, calls.StateFailed} {
		copy := *call
		copy.State = state
		if activeOutboundLocalHangup(&copy, channel, channel, "from-simson-out") {
			t.Fatalf("non-active leg ended another attempt: %s", state)
		}
	}
	for _, other := range []string{"Local/3101@from-simson-callback-source-00000001", "Local/09123208334@from-simson-out-extra-00000001", "PJSIP/1701-00000001"} {
		if activeOutboundLocalHangup(call, other, other, "from-simson-out") {
			t.Fatalf("unrelated helper is final: %s", other)
		}
	}
	if activeOutboundLocalHangup(call, channel, "Local/09123208334@from-simson-out-00000002", "from-simson-out") {
		t.Fatal("late failure from previous dial attempt ended the answered attempt")
	}
	call.ToNode = "sip:1027"
	call.GatewayTrunk = ""
	if activeOutboundLocalHangup(call, channel, channel, "from-simson-out") {
		t.Fatal("ordinary SIP call changed")
	}
}

func TestGatewaySnapshotRejectsErrorsAndIncompleteOutput(t *testing.T) {
	row := "PJSIP/1701-00000001!from-simson-out!!1!Up!AppDial!(Outgoing Line)!100!!!3!12!room!1.1"
	for _, output := range []string{"", "Permission denied", row, "No such command\n--END COMMAND--", "broken!row\n--END COMMAND--"} {
		if validGatewaySnapshot(output) {
			t.Fatalf("unsafe snapshot accepted: %q", output)
		}
	}
	for _, output := range []string{"--END COMMAND--", row + "\n--END COMMAND--"} {
		if !validGatewaySnapshot(output) {
			t.Fatal("complete snapshot rejected")
		}
	}
}

func TestGatewayRecoveryHandlesOrdinaryDeskCallsWithoutSilenceOrDurationLimits(t *testing.T) {
	now := time.Now()
	call := &calls.Call{State: calls.StateActive, AnsweredAt: now.Add(-48 * time.Hour)}
	var missingSince time.Time
	if gatewayRecoveryReason(call, nil, true, &missingSince, now, 20*time.Second) != "" {
		t.Fatal("healthy long call ended")
	}
	if gatewayRecoveryReason(call, nil, false, &missingSince, now, 20*time.Second) != "" {
		t.Fatal("transient bridge transition ended call")
	}
	if reason := gatewayRecoveryReason(call, nil, false, &missingSince, now.Add(20*time.Second), 20*time.Second); reason != "gateway_peer_missing" {
		t.Fatalf("ordinary desk phone orphan not recovered: %s", reason)
	}
	gatewayRecoveryReason(call, nil, true, &missingSince, now.Add(21*time.Second), 20*time.Second)
	if !missingSince.IsZero() {
		t.Fatal("restored peer did not reset grace")
	}
	missingSince = now.Add(time.Hour)
	gatewayRecoveryReason(call, nil, false, &missingSince, now, 20*time.Second)
	if !missingSince.Equal(now) {
		t.Fatal("clock reversal not reset")
	}
}

func TestGatewayPeerRequiresOwnAnsweredGatewayNotAnObserverOrAnotherCall(t *testing.T) {
	gateway := "PJSIP/1701-00000001"
	other := "PJSIP/1701-00000002"
	output := strings.Join([]string{
		gateway + "!ctx!!1!Up!AppDial!(Outgoing Line)!100!!!3!12!a!1.1",
		other + "!ctx!!1!Up!AppDial!(Outgoing Line)!100!!!3!12!b!2.1",
	}, "\n")
	if !gatewayPeerHealthy(output, []string{gateway}, "1701", 2) {
		t.Fatal("healthy gateway was not recognized")
	}
	if gatewayPeerHealthy(output, []string{"PJSIP/3101-00000003", "PJSIP/webrtc-pool-00000004"}, "1701", 2) {
		t.Fatal("observer or another call hid missing gateway")
	}
	if gatewayPeerHealthy(output, []string{gateway}, "170", 2) || gatewayPeerHealthy(output, []string{gateway}, "1701", 1) {
		t.Fatal("endpoint prefix collision or lone gateway counted as healthy")
	}
	if gatewayPeerHealthy(strings.ReplaceAll(output, "!Up!", "!Down!"), []string{gateway}, "1701", 2) {
		t.Fatal("down gateway counted as healthy")
	}
}
