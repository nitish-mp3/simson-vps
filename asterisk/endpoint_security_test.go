package asterisk

import (
	"strings"
	"testing"
)

func TestDirectSIPEndpointsRequireAuthenticatedSameAccountSource(t *testing.T) {
	endpoints := []SIPEndpointDef{
		{Extension: "1024", Username: "desk-auth", AccountID: "site-a", Enabled: true, CallbackBridge: true},
		{Extension: "1026", Username: "other-auth", AccountID: "site-a", Enabled: true},
		{Extension: "1701", AccountID: "site-a", Enabled: true},
		{Extension: "2024", AccountID: "site-b", Enabled: true},
		{Extension: "1029", AccountID: "site-a", Enabled: false},
	}
	allowed := endpointAccountSources(endpoints)["site-a"]
	for _, identity := range []string{"1024", "1026", "1701"} {
		if !strings.Contains(allowed, `"${CHANNEL(endpoint)}" = "`+identity+`"`) {
			t.Fatalf("same-account endpoint %s missing", identity)
		}
	}
	for _, unsafe := range []string{"2024", "1029", "desk-auth", "CALLERID", "anonymous"} {
		if strings.Contains(allowed, unsafe) {
			t.Fatalf("unsafe source identity in authorization: %s", unsafe)
		}
	}
	dialplan := buildDirectEndpointDialplan(endpoints)
	for _, start := range []string{"exten => 1024,1,NoOp", "exten => *1024,1,NoOp"} {
		route := section(dialplan, start, "exten => 1026,")
		guard := strings.Index(route, "outside its account")
		if guard < 0 || !strings.Contains(route, "Hangup(21)") || !strings.Contains(route, `"${CHANNEL(channeltype)}" = "Local"`) {
			t.Fatal("missing account guard or trusted internal Local compatibility")
		}
		for _, operation := range []string{"UserEvent(SimsonDirectCall", "SimsonIntercomCallback"} {
			if position := strings.Index(route, operation); position >= 0 && position < guard {
				t.Fatal("phone rang/callback emitted before source authorization")
			}
		}
	}
}

func TestEndpointIdentityUsesAsteriskCompatibleChannelFunction(t *testing.T) {
	endpoints := []SIPEndpointDef{
		{Extension: "1024", AccountID: "site-a", Enabled: true, CallbackBridge: true, AdvancedIngress: true},
		{Extension: "1603", AccountID: "site-a", Enabled: true},
	}
	generated := buildDirectEndpointDialplan(endpoints) + buildAdvancedIngressDialplan(endpoints) + buildAnonymousInboundDialplan([]string{"1701"}, endpoints)
	if strings.Contains(generated, "CHANNEL(pjsip,endpoint)") {
		t.Fatal("unsupported endpoint identity accessor would deny legitimate SIP calls")
	}
	if !strings.Contains(generated, "SourceEndpoint: ${CHANNEL(endpoint)}") || !strings.Contains(generated, "CallerEndpoint: ${CHANNEL(endpoint)}") {
		t.Fatal("authenticated endpoint identity is missing from SIP lifecycle events")
	}
}
