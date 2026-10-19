package config

import "testing"

func TestGatewayPeerGraceIsBoundedAndDefaultsWithoutChangingRTP(t *testing.T) {
	configuration := DefaultConfig()
	configuration.AdminToken = "fixture-only"
	if configuration.Asterisk.GatewayPeerGraceSec != 20 {
		t.Fatal("missing-peer grace default changed")
	}
	for _, value := range []int{-1, 0, 4, 301} {
		configuration.Asterisk.GatewayPeerGraceSec = value
		if configuration.Validate() == nil {
			t.Fatalf("unsafe grace accepted: %d", value)
		}
	}
	for _, value := range []int{5, 20, 300} {
		configuration.Asterisk.GatewayPeerGraceSec = value
		if err := configuration.Validate(); err != nil {
			t.Fatal(err)
		}
	}
	if len(configuration.Asterisk.GatewayRTPTimeouts) != 0 {
		t.Fatal("recovery changed RTP timeout profiles")
	}
}
