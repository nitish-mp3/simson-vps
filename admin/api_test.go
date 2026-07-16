package admin

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/nitish-mp3/simson-vps/store"
)

func TestSafeSIPUsernameRejectsBrokenAORNames(t *testing.T) {
	valid := []string{"1034", "desk-1", "door.cam_2", "WP813A3"}
	for _, username := range valid {
		if !isSafeSIPUsername(username) {
			t.Fatalf("expected username %q to be accepted", username)
		}
	}

	invalid := []string{"", "1", "WP813 A3", "desk/1", "door@site", "नमस्ते"}
	for _, username := range invalid {
		if isSafeSIPUsername(username) {
			t.Fatalf("expected username %q to be rejected", username)
		}
	}
}

func TestCallDurationRulesAreExactAndAccountScoped(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "simson.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	if err := st.CreateAccount("site-a", "Site A", 10, 10); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateAccount("site-b", "Site B", 10, 10); err != nil {
		t.Fatal(err)
	}
	for _, endpoint := range []store.SIPEndpoint{
		{ID: "source-a", AccountID: "site-a", Extension: "1027", Username: "site-a-1027", Password: "secret", Enabled: true, CallDurationRules: "{}"},
		{ID: "source-b", AccountID: "site-b", Extension: "1029", Username: "site-b-1029", Password: "secret", Enabled: true, CallDurationRules: "{}"},
	} {
		if err := st.CreateSIPEndpoint(endpoint); err != nil {
			t.Fatal(err)
		}
	}

	api := &API{store: st}
	encoded, err := api.normalizeCallDurationRules("site-a", "1028", map[string]int{"1027": 15})
	if err != nil {
		t.Fatal(err)
	}
	if encoded != `{"1027":15}` {
		t.Fatalf("encoded rules = %q", encoded)
	}

	invalid := []map[string]int{
		{"1028": 10}, // source and target are the same phone
		{"1029": 10}, // source belongs to another account
		{"9999": 10}, // source does not exist
		{"1027": 0},
		{"1027": 86401},
	}
	for _, rules := range invalid {
		if _, err := api.normalizeCallDurationRules("site-a", "1028", rules); err == nil {
			t.Fatalf("expected rules %#v to be rejected", rules)
		}
	}
}

func TestAdvancedRouteValidationIsAccountScopedAndCapabilitySafe(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "advanced-route-validation.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	for _, account := range []string{"site-a", "site-b"} {
		if err := st.CreateAccount(account, account, 10, 10); err != nil {
			t.Fatal(err)
		}
	}
	for _, endpoint := range []store.SIPEndpoint{
		{ID: "gateway-a", AccountID: "site-a", Extension: "7001", Username: "site-a-7001", Password: "secret", Enabled: true, CallDurationRules: "{}"},
		{ID: "phone-a-1", AccountID: "site-a", Extension: "1025", Username: "site-a-1025", Password: "secret", Enabled: true, CallDurationRules: "{}"},
		{ID: "phone-a-2", AccountID: "site-a", Extension: "1026", Username: "site-a-1026", Password: "secret", Enabled: true, CallDurationRules: "{}"},
		{ID: "phone-a-3", AccountID: "site-a", Extension: "1027", Username: "site-a-1027", Password: "secret", Enabled: true, CallDurationRules: "{}"},
		{ID: "phone-b", AccountID: "site-b", Extension: "2025", Username: "site-b-2025", Password: "secret", Enabled: true, CallDurationRules: "{}"},
	} {
		if err := st.CreateSIPEndpoint(endpoint); err != nil {
			t.Fatal(err)
		}
	}

	api := &API{store: st}
	route := store.AdvancedRoute{
		ID: "route-a", AccountID: "site-a", Name: "Main", IngressKind: "gateway", IngressValue: "7001", Enabled: true,
		Stages: []store.RouteStage{{
			Name: "Reception", RingSeconds: 10, AnswerMode: "first_answer",
			Targets: []store.RouteTarget{{Kind: "sip", Value: "1025", Enabled: true}},
		}},
	}
	if err := api.validateAdvancedRoute(&route); err != nil {
		t.Fatalf("valid first-answer route rejected: %v", err)
	}
	if route.Stages[0].MaxAnswered != 1 {
		t.Fatalf("first-answer route did not normalize max_answered: %#v", route.Stages[0])
	}
	invalidCallLimit := route
	invalidCallLimit.Stages = append([]store.RouteStage(nil), route.Stages...)
	invalidCallLimit.Stages[0].MaxCallSeconds = 5
	if err := api.validateAdvancedRoute(&invalidCallLimit); err == nil {
		t.Fatal("unsafe connected-call limit below 10 seconds was accepted")
	}
	validCallLimit := route
	validCallLimit.Stages = append([]store.RouteStage(nil), route.Stages...)
	validCallLimit.Stages[0].MaxCallSeconds = 30
	if err := api.validateAdvancedRoute(&validCallLimit); err != nil {
		t.Fatalf("valid connected-call limit rejected: %v", err)
	}

	repeatedAcrossStages := route
	repeatedAcrossStages.Stages = []store.RouteStage{
		{
			Name: "Reception", RingSeconds: 10, AnswerMode: "first_answer",
			Targets: []store.RouteTarget{{Kind: "sip", Value: "1025", Enabled: true}},
		},
		{
			Name: "Fallback", RingSeconds: 10, AnswerMode: "first_answer",
			Targets: []store.RouteTarget{{Kind: "sip", Value: "1025", Enabled: true}},
		},
	}
	if err := api.validateAdvancedRoute(&repeatedAcrossStages); err == nil {
		t.Fatal("same SIP destination was accepted in multiple route stages")
	}

	crossAccount := route
	crossAccount.Stages = []store.RouteStage{{
		Name: "Wrong site", RingSeconds: 10, AnswerMode: "first_answer",
		Targets: []store.RouteTarget{{Kind: "sip", Value: "2025", Enabled: true}},
	}}
	if err := api.validateAdvancedRoute(&crossAccount); err == nil {
		t.Fatal("cross-account SIP target was accepted")
	}

	privateHub := route
	privateHub.Enabled = false
	privateHub.Stages = []store.RouteStage{{
		Name: "Private operator", RingSeconds: 15, AnswerMode: "private_hub", MaxAnswered: 3,
		Targets: []store.RouteTarget{
			{Kind: "sip", Value: "1025", Role: "hub", Enabled: true},
			{Kind: "sip", Value: "1026", Role: "spoke", Enabled: true},
			{Kind: "sip", Value: "1027", Role: "spoke", Enabled: true},
		},
	}}
	if err := api.validateAdvancedRoute(&privateHub); err != nil {
		t.Fatalf("disabled, structurally valid private hub rejected: %v", err)
	}
	privateHub.Enabled = true
	if err := api.validateAdvancedRoute(&privateHub); err == nil {
		t.Fatal("private hub was enabled without isolated-media capability")
	}

	manual := route
	manual.IngressKind = "manual"
	manual.IngressValue = "security_alert"
	if err := api.validateAdvancedRoute(&manual); err == nil {
		t.Fatal("enabled manual route was accepted without a runtime trigger")
	}

	if err := st.CreateAdvancedRoute(route); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.SetPathValue("accountId", "site-b")
	request.SetPathValue("id", route.ID)
	response := httptest.NewRecorder()
	api.handleGetAdvancedRoute(response, request)
	if response.Code != http.StatusNotFound {
		t.Fatalf("cross-account route read status = %d, want %d", response.Code, http.StatusNotFound)
	}
}

func TestRouteToValidationIsAccountScopedButNotAvailabilityScoped(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "route-to-validation.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	for _, account := range []string{"site-a", "site-b"} {
		if err := st.CreateAccount(account, account, 10, 10); err != nil {
			t.Fatal(err)
		}
	}
	for _, node := range []struct {
		id, accountID, nodeType string
	}{
		{id: "haos-a", accountID: "site-a", nodeType: "haos"},
		{id: "haos-b", accountID: "site-b", nodeType: "haos"},
		{id: "asterisk-a", accountID: "site-a", nodeType: "asterisk"},
	} {
		if _, err := st.CreateNode(node.id, node.accountID, node.id, node.nodeType, `[]`); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.SetNodeEnabled("haos-a", false); err != nil {
		t.Fatal(err)
	}

	api := &API{store: st}
	response := httptest.NewRecorder()
	if !api.validRouteToNode(response, "site-a", "haos-a") {
		t.Fatalf("disabled same-account HAOS node was rejected: status=%d body=%s", response.Code, response.Body.String())
	}

	for _, routeTo := range []string{"haos-b", "asterisk-a", "missing"} {
		response = httptest.NewRecorder()
		if api.validRouteToNode(response, "site-a", routeTo) {
			t.Fatalf("invalid route_to %q was accepted", routeTo)
		}
		if response.Code != http.StatusBadRequest {
			t.Fatalf("route_to %q status=%d, want %d", routeTo, response.Code, http.StatusBadRequest)
		}
	}
}
