package server

import (
	"testing"

	"github.com/nitish-mp3/simson-vps/store"
)

func TestNativeVideoDoesNotBypassAdvancedAudioBehaviors(t *testing.T) {
	door := store.SIPEndpoint{Extension: "1604", Enabled: true, VideoEnabled: true}
	if !nativeVideoEndpoint(&door) {
		t.Fatal("plain video endpoint must use the native video route")
	}
	for _, change := range []func(*store.SIPEndpoint){
		func(endpoint *store.SIPEndpoint) { endpoint.Enabled = false },
		func(endpoint *store.SIPEndpoint) { endpoint.VideoEnabled = false },
		func(endpoint *store.SIPEndpoint) { endpoint.AutoAnswer = true },
		func(endpoint *store.SIPEndpoint) { endpoint.CallbackBridge = true },
		func(endpoint *store.SIPEndpoint) { endpoint.AnswerAnnouncement = "private_prompt" },
		func(endpoint *store.SIPEndpoint) { endpoint.CallDurationRules = `{"1024":60}` },
		func(endpoint *store.SIPEndpoint) { endpoint.DefaultOutbound = true },
	} {
		endpoint := door
		change(&endpoint)
		if nativeVideoEndpoint(&endpoint) {
			t.Fatal("native video bypassed an existing endpoint behavior")
		}
	}
}
