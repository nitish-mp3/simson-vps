package asterisk

import "testing"

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

func newTrackingOnlyRouter() *Router {
	return &Router{
		chanToCallID:          make(map[string]string),
		callIDToChan:          make(map[string]string),
		callIDToChannelPrefix: make(map[string][]string),
	}
}
