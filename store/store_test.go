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
}
