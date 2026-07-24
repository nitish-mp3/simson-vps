package asterisk

import (
	"bufio"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/nitish-mp3/simson-vps/logging"
)

func TestCallIDForChannelUsesPendingPrefix(t *testing.T) {
	r := newTrackingOnlyRouter()
	r.TrackPendingPrefix("call-1", "PJSIP/1027-")

	callID, ok := r.CallIDForChannel("PJSIP/1027-000333aa")
	if !ok {
		t.Fatal("expected pending PJSIP prefix to resolve a call ID")
	}
	if callID != "call-1" {
		t.Fatalf("callID = %q, want call-1", callID)
	}
}

func TestCallIDForChannelRejectsAmbiguousPendingPrefix(t *testing.T) {
	r := newTrackingOnlyRouter()
	r.TrackPendingPrefix("call-1", "PJSIP/1027-")
	r.TrackPendingPrefix("call-2", "PJSIP/1027-")

	if callID, ok := r.CallIDForChannel("PJSIP/1027-000333aa"); ok {
		t.Fatalf("ambiguous prefix resolved to %q, want no match", callID)
	}
}

func TestHangupTrackedCallNoWaitDoesNotWaitForAMIResponse(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	ami := &AMIClient{conn: clientConn, connected: true}
	r := newTrackingOnlyRouter()
	r.ami = ami
	r.TrackCall("call-gateway", "PJSIP/anonymous-0001")
	r.TrackCall("call-gateway", "PJSIP/1027-0002")

	received := make(chan string, 1)
	go func() {
		_ = serverConn.SetReadDeadline(time.Now().Add(time.Second))
		reader := bufio.NewReader(serverConn)
		var raw strings.Builder
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				received <- raw.String()
				return
			}
			raw.WriteString(line)
			if line == "\r\n" {
				received <- raw.String()
				return
			}
		}
	}()

	if err := r.HangupTrackedCallNoWait("call-gateway", "PJSIP/1027-0002"); err != nil {
		t.Fatalf("HangupTrackedCallNoWait() error = %v", err)
	}
	raw := <-received
	if !strings.Contains(raw, "Action: Hangup") || !strings.Contains(raw, "Channel: PJSIP/anonymous-0001") {
		t.Fatalf("unexpected AMI action: %q", raw)
	}
	if strings.Contains(raw, "PJSIP/1027-0002") {
		t.Fatalf("excluded channel was hung up: %q", raw)
	}
}

func TestHandleHangupPreservesCauseDetails(t *testing.T) {
	r := newTrackingOnlyRouter()
	r.TrackCall("call-1", "PJSIP/1027-0001")

	var got ChannelHangup
	r.OnChannelHangup = func(info ChannelHangup) { got = info }
	r.handleHangup(Event{Fields: map[string]string{
		"Channel":   "PJSIP/1027-0001",
		"Cause":     "16",
		"Cause-txt": "Normal Clearing",
		"Uniqueid":  "123.4",
		"Linkedid":  "123.1",
	}})

	if got.Channel != "PJSIP/1027-0001" || got.Cause != "16" || got.CauseText != "Normal Clearing" {
		t.Fatalf("hangup details = %+v", got)
	}
	if got.UniqueID != "123.4" || got.LinkedID != "123.1" {
		t.Fatalf("hangup correlation IDs = %+v", got)
	}
}

func TestHandleDTMFPreservesCompletedReceivedDigits(t *testing.T) {
	r := newTrackingOnlyRouter()
	var got []string
	r.OnChannelDTMF = func(info ChannelDTMF) { got = append(got, info.Digit) }

	for _, digit := range []string{"*", "8", "4", "1", "0", "2", "6"} {
		r.handleDTMF(Event{Fields: map[string]string{
			"Channel": "PJSIP/1027-0001;1", "Digit": digit, "Direction": "Received",
		}})
	}
	// Outbound DTMF is not a feature-code input and must be ignored.
	r.handleDTMF(Event{Fields: map[string]string{
		"Channel": "PJSIP/1027-0001", "Digit": "9", "Direction": "Sent",
	}})

	if joined := strings.Join(got, ""); joined != "*841026" {
		t.Fatalf("received DTMF = %q, want *841026", joined)
	}
}

func TestHandleDTMFAcceptsDigitReceivedOnDTMFEnd(t *testing.T) {
	r := newTrackingOnlyRouter()
	var got string
	r.OnChannelDTMF = func(info ChannelDTMF) { got = info.Digit }
	r.handleDTMF(Event{Fields: map[string]string{
		"Channel":       "PJSIP/1027-00000001",
		"DigitReceived": "*",
		"Direction":     "Received",
	}})
	if got != "*" {
		t.Fatalf("received DTMF = %q, want %q", got, "*")
	}
}

func TestEndpointCleanupChannelsIncludesLinkedAndBridgedLegs(t *testing.T) {
	output := strings.Join([]string{
		"PJSIP/7009-0001!from-simson-sip!100!1!Up!ConfBridge!bridge-a!100!!!10.1!10.1!bridge-a!",
		"Local/9123@from-simson-out-0001;1!from-simson-node!s!1!Up!ConfBridge!bridge-a!100!!!10.2!10.1!bridge-a!",
		"PJSIP/1027-0002!from-simson-extension!1027!1!Up!Dial!PJSIP/1028!1027!!!20.1!20.1!bridge-b!",
	}, "\n")
	got := endpointCleanupChannels(output, "7009")
	want := []string{"Local/9123@from-simson-out-0001;1", "PJSIP/7009-0001"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("cleanup channels = %v, want %v", got, want)
	}
}

func TestEndpointCleanupChannelsDoesNotCrossCalls(t *testing.T) {
	output := strings.Join([]string{
		"PJSIP/7009-0001!ctx!s!1!Up!Dial!x!100!!!10.1!10.1!bridge-a!",
		"PJSIP/7014-0002!ctx!s!1!Up!Dial!x!100!!!20.1!20.1!bridge-b!",
	}, "\n")
	got := endpointCleanupChannels(output, "7009")
	if len(got) != 1 || got[0] != "PJSIP/7009-0001" {
		t.Fatalf("cleanup crossed endpoint boundary: %v", got)
	}
}

func TestActiveEndpointChannelsRequiresAnsweredExactEndpoint(t *testing.T) {
	output := strings.Join([]string{
		"PJSIP/1027-0003!from-simson-extension!1028!1!Up!Dial!PJSIP/1028!1027!!!30.1!30.1!bridge-c!",
		"PJSIP/1027-0002!from-simson-extension!1028!1!Ringing!Dial!PJSIP/1028!1027!!!20.1!20.1!!",
		"PJSIP/10270-0001!from-simson-extension!1028!1!Up!Dial!PJSIP/1028!10270!!!10.1!10.1!bridge-a!",
		"PJSIP/1028-0004!from-simson-extension!1027!1!Up!AppDial!(Outgoing Line)!1028!!!30.2!30.1!bridge-c!",
	}, "\n")
	got := activeEndpointChannels(output, "1027")
	if len(got) != 1 || got[0] != "PJSIP/1027-0003" {
		t.Fatalf("active channels = %v, want exact answered 1027 channel", got)
	}
}

func TestActiveEndpointChannelsReturnsStableAmbiguousSet(t *testing.T) {
	output := strings.Join([]string{
		"PJSIP/1027-0009!ctx!s!1!Up!Dial!x!1027!!!90.1!90.1!b!",
		"PJSIP/1027-0001!ctx!s!1!Up!Dial!x!1027!!!10.1!10.1!a!",
	}, "\n")
	got := activeEndpointChannels(output, "1027")
	want := []string{"PJSIP/1027-0001", "PJSIP/1027-0009"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("active channels = %v, want %v", got, want)
	}
}

func TestBridgeTransferOriginateFailureDoesNotReachParentCallCallback(t *testing.T) {
	r := newTrackingOnlyRouter()
	r.bridgeTransfers["transfer-action"] = pendingBridgeTransfer{
		callID: "call-1", sourceChannel: "PJSIP/1027-0001", sourceExt: "1027", targetExt: "1026", replaceSource: true,
	}
	resultCh := make(chan BridgeTransferResult, 1)
	parentResult := make(chan struct{}, 1)
	r.OnBridgeTransfer = func(result BridgeTransferResult) { resultCh <- result }
	r.OnOriginateResult = func(string, bool, string) { parentResult <- struct{}{} }

	r.handleOriginateResponse(Event{Fields: map[string]string{
		"ActionID": "transfer-action", "Response": "Failure", "Reason": "4",
	}})

	select {
	case result := <-resultCh:
		if result.OK || result.CallID != "call-1" || result.SourceExt != "1027" || result.TargetExt != "1026" || !result.ReplaceSource {
			t.Fatalf("unexpected bridge transfer result: %+v", result)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for bridge transfer result")
	}
	select {
	case <-parentResult:
		t.Fatal("failed transfer was incorrectly reported as a parent call originate failure")
	case <-time.After(30 * time.Millisecond):
	}
}

func newTrackingOnlyRouter() *Router {
	return &Router{
		log:                   logging.New("error"),
		chanToCallID:          make(map[string]string),
		callIDToChan:          make(map[string]string),
		callIDToChannelPrefix: make(map[string][]string),
		actionIDToCallID:      make(map[string]string),
		bridgeTransfers:       make(map[string]pendingBridgeTransfer),
	}
}
