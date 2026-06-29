package server

import (
	"reflect"
	"testing"
	"time"

	"github.com/nitish-mp3/simson-vps/asterisk"
	"github.com/nitish-mp3/simson-vps/calls"
)

func TestOutboundGatewayDialCandidatesIncludeLandlineMobilePrefix(t *testing.T) {
	got := outboundGatewayDialCandidates("919123208334", "9123208334", false)
	want := []string{"9123208334", "919123208334", "09123208334"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("outboundGatewayDialCandidates() = %#v, want %#v", got, want)
	}
}

func TestOutboundGatewayDialCandidatesPreferLandlineMobilePrefixForFXO(t *testing.T) {
	got := outboundGatewayDialCandidates("919123208334", "9123208334", true)
	want := []string{"09123208334", "9123208334", "919123208334"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("outboundGatewayDialCandidates() = %#v, want %#v", got, want)
	}
}

func TestOutboundGatewayDialCandidatesKeepShortIntercomExtensionSingleForm(t *testing.T) {
	got := outboundGatewayDialCandidates("7013198", "198", true)
	want := []string{"198"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("outboundGatewayDialCandidates() = %#v, want %#v", got, want)
	}
}

func TestStripOutboundTrunkPrefixSupportsShortIntercomExtension(t *testing.T) {
	got := stripOutboundTrunkPrefix("7013198", "7013")
	if got != "198" {
		t.Fatalf("stripOutboundTrunkPrefix() = %q, want %q", got, "198")
	}
}

func TestSuppressIncomingSIPInviteUsesGatewaySourceInsteadOfAnonymous(t *testing.T) {
	s := &Server{calls: calls.NewManager(), recentSIPInvites: map[string]time.Time{}}
	in := asterisk.IncomingSIPCall{
		Channel:       "PJSIP/anonymous-00000001",
		Extension:     "7013",
		CallerID:      "919123208334",
		GatewaySource: "7013",
		BridgeID:      "bridge-1",
	}
	if s.shouldSuppressIncomingSIPInvite("acct", in, "7013") {
		t.Fatal("first anonymous gateway invite should not be suppressed")
	}
	in.GatewaySource = "7014"
	if s.shouldSuppressIncomingSIPInvite("acct", in, "7014") {
		t.Fatal("different gateway source must not collide under generic anonymous endpoint")
	}
}

func TestSIPOutboundDialCandidatesIncludeLandlineMobilePrefix(t *testing.T) {
	got := sipOutboundDialCandidates("9123208334")
	want := []string{"9123208334", "919123208334", "09123208334"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("sipOutboundDialCandidates() = %#v, want %#v", got, want)
	}
}
