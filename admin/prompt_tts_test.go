package admin

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNormalizeAnswerPromptText(t *testing.T) {
	got, err := normalizeAnswerPromptText("  Call   for Amit.\nPlease wait.  ")
	if err != nil {
		t.Fatal(err)
	}
	if got != "Call for Amit. Please wait." {
		t.Fatalf("unexpected normalized prompt: %q", got)
	}
	if _, err := normalizeAnswerPromptText(strings.Repeat("x", maxAnswerPromptRunes+1)); err == nil {
		t.Fatal("overlong prompt must be rejected")
	}
}

func TestPromptSynthesizerFailsClosedWithoutEngine(t *testing.T) {
	p := &promptSynthesizer{root: t.TempDir(), voice: "en-us", rate: "150"}
	_, err := p.Generate(context.Background(), "site-a", "endpoint-a", "Call for Amit.")
	if !errors.Is(err, errPromptTTSEngineUnavailable) {
		t.Fatalf("expected unavailable speech engine, got %v", err)
	}
}

func TestPromptSynthesizerUsesAsteriskDataSoundRoot(t *testing.T) {
	t.Setenv("SIMSON_TTS_SOUND_DIR", "")
	p := newPromptSynthesizer()
	if p.root != defaultPromptSoundRoot {
		t.Fatalf("unexpected default prompt root: %q", p.root)
	}
}

func TestPromptSynthesizerClassifiesReadOnlyStorage(t *testing.T) {
	// A regular file cannot contain the account-scoped prompt directory. This
	// produces the same MkdirAll failure on Windows and Unix without relying on
	// chmod semantics or the user running the test.
	root := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(root, []byte("occupied"), 0o600); err != nil {
		t.Fatal(err)
	}
	p := &promptSynthesizer{
		root: root, voice: "en-us", rate: "150",
		espeak: "unused-espeak", sox: "unused-sox",
	}
	_, err := p.Generate(context.Background(), "site-a", "endpoint-a", "Call for Amit.")
	if !errors.Is(err, errPromptStorageUnavailable) {
		t.Fatalf("expected storage-unavailable error, got %v", err)
	}
}

func TestPromptCleanupIsEndpointAndAccountScoped(t *testing.T) {
	root := t.TempDir()
	p := &promptSynthesizer{root: root}
	account := shortPromptHash("site-a", 16)
	endpoint := shortPromptHash("endpoint-a", 16)
	dir := filepath.Join(root, account)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	keep := "endpoint_" + endpoint + "_keep.wav"
	secondKeep := "endpoint_" + endpoint + "_second.wav"
	remove := "endpoint_" + endpoint + "_old.wav"
	other := "endpoint_" + shortPromptHash("endpoint-b", 16) + "_other.wav"
	for _, name := range []string{keep, secondKeep, remove, other} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("wav"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	p.CleanupEndpoint(
		"site-a",
		"endpoint-a",
		filepath.ToSlash(filepath.Join("simson", account, strings.TrimSuffix(keep, ".wav"))),
		filepath.ToSlash(filepath.Join("simson", account, strings.TrimSuffix(secondKeep, ".wav"))),
	)
	if _, err := os.Stat(filepath.Join(dir, keep)); err != nil {
		t.Fatalf("current prompt was removed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, secondKeep)); err != nil {
		t.Fatalf("second current prompt was removed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, remove)); !os.IsNotExist(err) {
		t.Fatalf("stale prompt was not removed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, other)); err != nil {
		t.Fatalf("another endpoint's prompt was removed: %v", err)
	}
}
