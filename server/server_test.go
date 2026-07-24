package server

import (
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/nitish-mp3/simson-vps/asterisk"
	"github.com/nitish-mp3/simson-vps/calls"
	"github.com/nitish-mp3/simson-vps/config"
	"github.com/nitish-mp3/simson-vps/store"
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

func TestGatewayDialProfileKeepsGrandstreamFXODirect(t *testing.T) {
	leadingZero, postAnswer := gatewayDialProfileFromMetadata("7014 grandstream port 1 airtel fxo landline")
	if leadingZero || postAnswer != "" {
		t.Fatalf("Grandstream profile = leadingZero:%v postAnswer:%q, want direct dialing", leadingZero, postAnswer)
	}
}

func TestGatewayDialProfilePreservesSynwayTwoStageDial(t *testing.T) {
	leadingZero, postAnswer := gatewayDialProfileFromMetadata("7009 synway smg4008 gsm active port")
	if !leadingZero || postAnswer != "#" {
		t.Fatalf("Synway profile = leadingZero:%v postAnswer:%q, want leading zero and #", leadingZero, postAnswer)
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

func TestHAOSRingCode(t *testing.T) {
	if !isHAOSRingCode("100") {
		t.Fatal("100 should be the reserved HAOS ring code")
	}
	if !isHAOSRingCode("*100") || !isHAOSBypassCode("*100") {
		t.Fatal("*100 should explicitly bypass advanced SIP routes and ring HAOS")
	}
	if isHAOSBypassCode("100") {
		t.Fatal("100 remains available as the advanced route trigger")
	}
	if isHAOSRingCode("1001") {
		t.Fatal("normal SIP extensions must not be treated as the HAOS ring code")
	}
}

func TestSuppressIncomingSIPInviteUsesFixedDebounceWindow(t *testing.T) {
	s := &Server{calls: calls.NewManager(), recentSIPInvites: map[string]time.Time{}}
	in := asterisk.IncomingSIPCall{
		Channel:   "PJSIP/1027-00000001",
		Extension: "100",
		CallerID:  "1027",
		BridgeID:  "bridge-1",
	}
	if s.shouldSuppressIncomingSIPInvite("acct", in, "1027") {
		t.Fatal("first invite should not be suppressed")
	}
	key := "acct|100|1027|1027"
	original := s.recentSIPInvites[key]
	if !s.shouldSuppressIncomingSIPInvite("acct", in, "1027") {
		t.Fatal("immediate duplicate should be suppressed")
	}
	if got := s.recentSIPInvites[key]; !got.Equal(original) {
		t.Fatalf("suppressed retry moved debounce timestamp from %v to %v", original, got)
	}
}

func TestGatewaySelectionDoesNotLeakDefaultTrunkAcrossAccounts(t *testing.T) {
	st := newServerTestStore(t)
	if err := st.CreateAccount("site-a", "Site A", 10, 5); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateAccount("site-b", "Site B", 10, 5); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateSIPEndpoint(store.SIPEndpoint{
		ID:              "gw-a",
		AccountID:       "site-a",
		Extension:       "7009",
		Username:        "7009",
		Password:        "secret",
		Description:     "Synway gateway",
		DefaultOutbound: true,
		Enabled:         true,
	}); err != nil {
		t.Fatal(err)
	}

	s := &Server{store: st, cfg: config.DefaultConfig()}
	if got := s.selectOutboundGatewayTrunk("site-b", "919123208334"); got != "" {
		t.Fatalf("selectOutboundGatewayTrunk leaked trunk %q into another account", got)
	}
	if s.hasExplicitGatewayTrunkPrefix("site-b", "70099123208334") {
		t.Fatal("explicit gateway prefix from another account should not be accepted")
	}
	if s.isUsableOutboundGatewayTrunk("site-b", "7009") {
		t.Fatal("gateway trunk from another account should not be usable")
	}
	if got := s.selectOutboundGatewayTrunk("site-a", "919123208334"); got != "7009" {
		t.Fatalf("selectOutboundGatewayTrunk() = %q, want 7009", got)
	}
}

func TestSIPPhoneOutboundGatewayPrefersSourceGatewayUnlessPrefixOverrides(t *testing.T) {
	st := newServerTestStore(t)
	if err := st.CreateAccount("site-a", "Site A", 10, 5); err != nil {
		t.Fatal(err)
	}
	endpoints := []store.SIPEndpoint{
		{ID: "gw-default", AccountID: "site-a", Extension: "7009", Username: "7009", Password: "secret", Description: "Synway", DefaultOutbound: true, Enabled: true},
		{ID: "gw-fxo", AccountID: "site-a", Extension: "7014", Username: "7014", Password: "secret", Description: "Grandstream FXO", Enabled: true},
		{ID: "phone", AccountID: "site-a", Extension: "1027", Username: "1027", Password: "secret", Description: "Desk phone", Enabled: true},
	}
	for _, ep := range endpoints {
		if err := st.CreateSIPEndpoint(ep); err != nil {
			t.Fatal(err)
		}
	}

	s := &Server{store: st, cfg: config.DefaultConfig()}
	gatewayCaller := &store.SIPEndpoint{AccountID: "site-a", Extension: "7014", Enabled: true}
	if got := s.selectSIPPhoneOutboundGatewayTrunk(gatewayCaller, "9123208334"); got != "7014" {
		t.Fatalf("source gateway trunk = %q, want 7014", got)
	}
	if got := s.selectSIPPhoneOutboundGatewayTrunk(gatewayCaller, "70099123208334"); got != "7009" {
		t.Fatalf("explicit gateway prefix trunk = %q, want 7009", got)
	}
	deskCaller := &store.SIPEndpoint{AccountID: "site-a", Extension: "1027", Enabled: true}
	if got := s.selectSIPPhoneOutboundGatewayTrunk(deskCaller, "9123208334"); got != "7009" {
		t.Fatalf("desk phone default trunk = %q, want 7009", got)
	}
}

func TestAdvancedRouteDeclineKeepsOtherHAOSDestination(t *testing.T) {
	run := &advancedRouteRun{
		invitedNodes: map[string]bool{"haos-a": true, "haos-b": true},
		children:     map[string]*advancedRouteLeg{},
	}
	s := &Server{advancedRoutes: map[string]*advancedRouteRun{"call-1": run}}

	gotRun, keepRouting, handled := s.declineAdvancedRouteNode("call-1", "haos-a")
	if !handled || !keepRouting || gotRun != run {
		t.Fatalf("decline result = run:%p keep:%t handled:%t", gotRun, keepRouting, handled)
	}
	if run.invitedNodes["haos-a"] || !run.invitedNodes["haos-b"] {
		t.Fatalf("remaining invitees = %#v", run.invitedNodes)
	}
}

func TestAdvancedRouteDeclineKeepsRingingSIPDestination(t *testing.T) {
	run := &advancedRouteRun{
		invitedNodes: map[string]bool{"haos-a": true},
		children: map[string]*advancedRouteLeg{
			"leg-1": {parentID: "call-1"},
		},
	}
	s := &Server{advancedRoutes: map[string]*advancedRouteRun{"call-1": run}}

	_, keepRouting, handled := s.declineAdvancedRouteNode("call-1", "haos-a")
	if !handled || !keepRouting {
		t.Fatalf("decline with SIP child = keep:%t handled:%t", keepRouting, handled)
	}
}

func TestAdvancedRouteDeclineEndsAtFinalDestination(t *testing.T) {
	run := &advancedRouteRun{
		invitedNodes: map[string]bool{"haos-a": true},
		children:     map[string]*advancedRouteLeg{},
	}
	s := &Server{advancedRoutes: map[string]*advancedRouteRun{"call-1": run}}

	_, keepRouting, handled := s.declineAdvancedRouteNode("call-1", "haos-a")
	if !handled || keepRouting {
		t.Fatalf("final decline = keep:%t handled:%t", keepRouting, handled)
	}
}

func TestAdvancedRouteTargetKeyTreatsSIPAndGatewayAsSameEndpoint(t *testing.T) {
	sipKey := advancedRouteTargetKey(store.RouteTarget{Kind: "sip", Value: "1025"})
	gatewayKey := advancedRouteTargetKey(store.RouteTarget{Kind: "gateway", Value: "1025"})
	if sipKey != gatewayKey {
		t.Fatalf("SIP and gateway aliases produced different keys: %q != %q", sipKey, gatewayKey)
	}
	externalA := advancedRouteTargetKey(store.RouteTarget{Kind: "external", Value: "919123208334", Trunk: "7009"})
	externalB := advancedRouteTargetKey(store.RouteTarget{Kind: "external", Value: "919123208334", Trunk: "7013"})
	if externalA == externalB {
		t.Fatalf("external targets on different trunks collided: %q", externalA)
	}
}

func TestAdvancedRouteSourceUsesCallingPhoneNotDialledDestination(t *testing.T) {
	st := newServerTestStore(t)
	if err := st.CreateAccount("site-a", "Site A", 10, 5); err != nil {
		t.Fatal(err)
	}
	for _, extension := range []string{"1027", "1028"} {
		if err := st.CreateSIPEndpoint(store.SIPEndpoint{
			ID: extension, AccountID: "site-a", Extension: extension,
			Username: extension, Password: "secret", Enabled: true,
		}); err != nil {
			t.Fatal(err)
		}
	}
	s := &Server{store: st, cfg: config.DefaultConfig()}
	in := asterisk.IncomingSIPCall{
		Channel:        "PJSIP/1027-00000001",
		CallerEndpoint: "1027",
		CallerID:       "1027",
		Extension:      "1028",
	}
	if got := s.resolveAdvancedRouteSource("site-a", "1028", in); got != "1027" {
		t.Fatalf("advanced route source = %q, want calling phone 1027", got)
	}
}

func TestAdvancedRouteSourceDoesNotCrossAccountBoundary(t *testing.T) {
	st := newServerTestStore(t)
	for _, account := range []string{"site-a", "site-b"} {
		if err := st.CreateAccount(account, account, 10, 5); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.CreateSIPEndpoint(store.SIPEndpoint{
		ID: "phone-b", AccountID: "site-b", Extension: "2027",
		Username: "2027", Password: "secret", Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	s := &Server{store: st, cfg: config.DefaultConfig()}
	in := asterisk.IncomingSIPCall{
		Channel: "PJSIP/2027-00000001", CallerEndpoint: "2027", Extension: "1028",
	}
	if got := s.resolveAdvancedRouteSource("site-a", "1028", in); got != "1028" {
		t.Fatalf("cross-account source = %q, want safe fallback 1028", got)
	}
}

func TestAdvancedRouteLandingCandidatesPreferDialledPhone(t *testing.T) {
	got := advancedRouteLandingCandidates("1040", "1040", "1040", "1027")
	if len(got) != 1 || got[0] != "1040" {
		t.Fatalf("landing candidates = %#v, want [1040]", got)
	}

	got = advancedRouteLandingCandidates("7014", "7014", "1040", "7014")
	if len(got) != 1 || got[0] != "1040" {
		t.Fatalf("resolved gateway landing candidates = %#v, want [1040]", got)
	}
}

func TestRouteForHAOSRingCodeHonorsGatewayDirectTarget(t *testing.T) {
	tests := []struct {
		name      string
		endpoint  *store.SIPEndpoint
		wantRoute string
		wantHAOS  bool
	}{
		{
			name: "direct gateway uses its selected SIP destination",
			endpoint: &store.SIPEndpoint{
				Extension: "7014", GatewayInboundMode: "direct_target", GatewayDirectTarget: "1027",
			},
			wantRoute: "1027",
		},
		{
			name: "gateway configured for HAOS keeps extension 100 behavior",
			endpoint: &store.SIPEndpoint{
				Extension: "7014", GatewayInboundMode: "haos_then_fallback", GatewayDirectTarget: "1027",
			},
			wantHAOS: true,
		},
		{
			name: "ordinary SIP phone still rings HAOS",
			endpoint: &store.SIPEndpoint{
				Extension: "1027",
			},
			wantHAOS: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			route, haos := routeForHAOSRingCode(test.endpoint)
			if route != test.wantRoute || haos != test.wantHAOS {
				t.Fatalf("routeForHAOSRingCode() = (%q, %v), want (%q, %v)", route, haos, test.wantRoute, test.wantHAOS)
			}
		})
	}
}

func newServerTestStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "simson.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}
