package server

import (
	"reflect"
	"testing"
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

func TestSIPOutboundDialCandidatesIncludeLandlineMobilePrefix(t *testing.T) {
	got := sipOutboundDialCandidates("9123208334")
	want := []string{"9123208334", "919123208334", "09123208334"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("sipOutboundDialCandidates() = %#v, want %#v", got, want)
	}
}
