package admin

import (
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
