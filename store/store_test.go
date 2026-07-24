package store

import (
	"database/sql"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

func TestOpenMigratesLegacySIPEndpointsWithVideoFlag(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	for _, stmt := range []string{
		`CREATE TABLE accounts (id TEXT PRIMARY KEY, name TEXT NOT NULL, license_status TEXT NOT NULL DEFAULT 'active', max_nodes INTEGER NOT NULL DEFAULT 10, max_calls INTEGER NOT NULL DEFAULT 5, created_at DATETIME NOT NULL DEFAULT (datetime('now')), updated_at DATETIME NOT NULL DEFAULT (datetime('now')))`,
		`INSERT INTO accounts (id, name) VALUES ('site-a', 'Site A')`,
		`CREATE TABLE sip_endpoints (id TEXT PRIMARY KEY, account_id TEXT NOT NULL REFERENCES accounts(id), extension TEXT NOT NULL, username TEXT NOT NULL UNIQUE, password TEXT NOT NULL, description TEXT NOT NULL DEFAULT '', route_to TEXT NOT NULL DEFAULT '', enabled INTEGER NOT NULL DEFAULT 1, created_at DATETIME NOT NULL DEFAULT (datetime('now')), updated_at DATETIME NOT NULL DEFAULT (datetime('now')))`,
		`INSERT INTO sip_endpoints (id, account_id, extension, username, password) VALUES ('door', 'site-a', '1101', 'door', 'secret')`,
	} {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	door, err := store.GetSIPEndpoint("door")
	if err != nil {
		t.Fatal(err)
	}
	if door == nil {
		t.Fatal("legacy SIP endpoint missing after migration")
	}
	if door.VideoEnabled {
		t.Fatal("legacy SIP endpoint should remain audio-only by default")
	}

	if door.AutoAnswer {
		t.Fatal("legacy SIP endpoint should not auto-answer by default")
	}
	if door.AnswerAnnouncement != "" {
		t.Fatalf("legacy SIP endpoint should not gain an answer announcement: %q", door.AnswerAnnouncement)
	}
	if door.AnswerAnnouncementText != "" {
		t.Fatalf("legacy SIP endpoint should not gain answer prompt text: %q", door.AnswerAnnouncementText)
	}
	if door.PreRingAnnouncement != "" || door.PreRingAnnouncementText != "" {
		t.Fatalf("legacy SIP endpoint should not gain a pre-ring prompt: %#v", door)
	}
	if door.CallDurationRules != "{}" {
		t.Fatalf("legacy SIP endpoint should default to unlimited calls, got %q", door.CallDurationRules)
	}
	if door.SupervisionConfig != "{}" {
		t.Fatalf("legacy SIP endpoint should default to disabled supervision, got %q", door.SupervisionConfig)
	}

	if err := store.UpdateSIPEndpoint(door.ID, door.Description, door.Password, door.RouteTo, true, true, "1025", true, "1602", true, "1025", true, true, false, door.Enabled); err != nil {
		t.Fatal(err)
	}
	door, err = store.GetSIPEndpoint("door")
	if err != nil {
		t.Fatal(err)
	}
	if !door.VideoEnabled {
		t.Fatal("video_enabled update was not persisted")
	}
	if !door.AutoAnswer {
		t.Fatal("auto_answer update was not persisted")
	}
	if door.AutoAnswerCallers != "1025" {
		t.Fatalf("auto_answer_callers update was not persisted: %q", door.AutoAnswerCallers)
	}
	if !door.AutoSpeaker {
		t.Fatal("auto_speaker update was not persisted")
	}
	if door.AutoSpeakerCallers != "1602" {
		t.Fatalf("auto_speaker_callers update was not persisted: %q", door.AutoSpeakerCallers)
	}
	if !door.CallbackBridge || door.CallbackBridgeCallers != "1025" || !door.CallbackCallerAutoAnswer || !door.CallbackCallerAutoSpeaker {
		t.Fatalf("callback bridge fields were not persisted: %#v", door)
	}
	if err := store.UpdateSIPEndpointAnnouncement(door.ID, "simson/site-a/call_for_amit", "Call for Amit."); err != nil {
		t.Fatal(err)
	}
	door, err = store.GetSIPEndpoint("door")
	if err != nil {
		t.Fatal(err)
	}
	if door.AnswerAnnouncement != "simson/site-a/call_for_amit" {
		t.Fatalf("answer announcement update was not persisted: %q", door.AnswerAnnouncement)
	}
	if door.AnswerAnnouncementText != "Call for Amit." {
		t.Fatalf("answer prompt text update was not persisted: %q", door.AnswerAnnouncementText)
	}

	if err := store.UpdateSIPEndpointCallBehavior(
		door.ID,
		"simson/site-a/after_answer",
		"Call for Amit.",
		"simson/site-a/before_ring",
		"Please wait while I call Amit.",
		`{"1025":15}`,
	); err != nil {
		t.Fatal(err)
	}
	door, err = store.GetSIPEndpoint("door")
	if err != nil {
		t.Fatal(err)
	}
	if door.AnswerAnnouncement != "simson/site-a/after_answer" || door.AnswerAnnouncementText != "Call for Amit." {
		t.Fatalf("answer-stage prompt was not persisted: %#v", door)
	}
	if door.PreRingAnnouncement != "simson/site-a/before_ring" || door.PreRingAnnouncementText != "Please wait while I call Amit." {
		t.Fatalf("pre-ring prompt was not persisted: %#v", door)
	}
	if door.CallDurationRules != `{"1025":15}` {
		t.Fatalf("route duration rules were not persisted: %q", door.CallDurationRules)
	}
	policy := `{"enabled":true,"listen":true,"listen_key":"*81","targets":["1025"]}`
	if err := store.UpdateSIPEndpointSupervision(door.ID, policy); err != nil {
		t.Fatal(err)
	}
	door, err = store.GetSIPEndpoint("door")
	if err != nil {
		t.Fatal(err)
	}
	if door.SupervisionConfig != policy {
		t.Fatalf("supervision policy was not persisted: %q", door.SupervisionConfig)
	}
}

func TestAccountCallFeaturesDefaultAndUpdate(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "features.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.CreateAccount("site-a", "Site A", 10, 10); err != nil {
		t.Fatal(err)
	}

	features, err := st.GetAccountCallFeatures("site-a")
	if err != nil {
		t.Fatal(err)
	}
	if features.TransferCode != "*84" || features.ConferenceCode != "*85" ||
		features.InviteListenCode != "*86" || features.InviteWhisperCode != "*87" ||
		features.InviteBargeCode != "*88" || !features.Enabled {
		t.Fatalf("unexpected defaults: %#v", features)
	}
	listed, err := st.ListAccountCallFeatures()
	if err != nil {
		t.Fatal(err)
	}
	if len(listed) != 1 || listed[0].AccountID != "site-a" || listed[0].TransferCode != "*84" || listed[0].ConferenceCode != "*85" || !listed[0].Enabled || listed[0].UpdatedAt.IsZero() {
		t.Fatalf("existing account defaults were not listed: %#v", listed)
	}

	want := AccountCallFeatures{
		AccountID: "site-a", TransferCode: "*64", ConferenceCode: "*65",
		InviteListenCode: "*66", InviteWhisperCode: "*67", InviteBargeCode: "*68", Enabled: true,
	}
	if err := st.UpsertAccountCallFeatures(want); err != nil {
		t.Fatal(err)
	}
	features, err = st.GetAccountCallFeatures("site-a")
	if err != nil {
		t.Fatal(err)
	}
	if features.TransferCode != want.TransferCode || features.ConferenceCode != want.ConferenceCode ||
		features.InviteListenCode != want.InviteListenCode || features.InviteWhisperCode != want.InviteWhisperCode ||
		features.InviteBargeCode != want.InviteBargeCode || !features.Enabled {
		t.Fatalf("account feature update was not persisted: %#v", features)
	}
}

func TestGetSIPEndpointByAccountAndExtensionIsTenantScoped(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "tenant-sip.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	for _, accountID := range []string{"site-a", "site-b"} {
		if err := st.CreateAccount(accountID, accountID, 10, 10); err != nil {
			t.Fatal(err)
		}
	}
	for _, ep := range []SIPEndpoint{
		{ID: "site-a-1040", AccountID: "site-a", Extension: "1040", Username: "site-a-1040", Password: "secret-a", Description: "Site A phone", Enabled: true},
		{ID: "site-b-1040", AccountID: "site-b", Extension: "1040", Username: "site-b-1040", Password: "secret-b", Description: "Site B phone", Enabled: true},
	} {
		if err := st.CreateSIPEndpoint(ep); err != nil {
			t.Fatal(err)
		}
	}

	got, err := st.GetSIPEndpointByAccountAndExtension("site-b", "1040")
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.ID != "site-b-1040" || got.AccountID != "site-b" {
		t.Fatalf("tenant-scoped lookup returned wrong endpoint: %#v", got)
	}
	got, err = st.GetSIPEndpointByAccountAndExtension("site-a", "9999")
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Fatalf("missing tenant endpoint should return nil, got %#v", got)
	}
}

func TestAdvancedRouteCRUDAndIngressLookup(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "advanced-routes.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.CreateAccount("site-a", "Site A", 10, 10); err != nil {
		t.Fatal(err)
	}

	route := AdvancedRoute{
		ID: "route-main", AccountID: "site-a", Name: "Main line", IngressKind: "gateway", IngressValue: "7001", Enabled: true,
		Stages: []RouteStage{{
			ID: "stage-1", Name: "Reception", RingSeconds: 15, AnswerMode: "first_answer", MaxAnswered: 1,
			Targets: []RouteTarget{{ID: "target-1", Kind: "sip", Value: "1025", Enabled: true}},
		}},
	}
	if err := st.CreateAdvancedRoute(route); err != nil {
		t.Fatal(err)
	}
	got, err := st.GetAdvancedRouteByIngress("site-a", "gateway", "7001")
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.Name != "Main line" || len(got.Stages) != 1 || got.Stages[0].Targets[0].Value != "1025" {
		t.Fatalf("unexpected route after create: %#v", got)
	}

	route.Name = "Main line escalation"
	route.Stages = append(route.Stages, RouteStage{
		ID: "stage-2", Name: "Backup", RingSeconds: 20, AnswerMode: "conference", MaxAnswered: 2,
		Targets: []RouteTarget{{ID: "target-2", Kind: "sip", Value: "1026", Enabled: true}},
	})
	if err := st.UpdateAdvancedRoute(route); err != nil {
		t.Fatal(err)
	}
	routes, err := st.ListAdvancedRoutes("site-a")
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) != 1 || routes[0].Name != route.Name || len(routes[0].Stages) != 2 {
		t.Fatalf("unexpected routes after update: %#v", routes)
	}

	if err := st.DeleteAdvancedRoute(route.ID, route.AccountID); err != nil {
		t.Fatal(err)
	}
	got, err = st.GetAdvancedRoute(route.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Fatalf("route still exists after delete: %#v", got)
	}
}
