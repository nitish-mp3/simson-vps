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

func newTrackingOnlyRouter() *Router {
	return &Router{
		log:                   logging.New("error"),
		chanToCallID:          make(map[string]string),
		callIDToChan:          make(map[string]string),
		callIDToChannelPrefix: make(map[string][]string),
	}
}
