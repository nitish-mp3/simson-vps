package admin

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"
)

const maxAnswerPromptRunes = 300

var errPromptTTSEngineUnavailable = errors.New("offline prompt speech engine is unavailable")
var errPromptStorageUnavailable = errors.New("prompt sound storage is unavailable")

// promptSynthesizer turns account-scoped endpoint text into an Asterisk sound.
// Commands receive text as a direct argv value, never through a shell.
type promptSynthesizer struct {
	root   string
	voice  string
	rate   string
	espeak string
	sox    string
	mu     sync.Mutex
}

func newPromptSynthesizer() *promptSynthesizer {
	root := strings.TrimSpace(os.Getenv("SIMSON_TTS_SOUND_DIR"))
	if root == "" {
		root = "/var/lib/asterisk/sounds/simson"
	}
	voice := strings.TrimSpace(os.Getenv("SIMSON_TTS_VOICE"))
	if voice == "" {
		voice = "en-us"
	}
	rate := strings.TrimSpace(os.Getenv("SIMSON_TTS_RATE"))
	if rate == "" {
		rate = "150"
	}
	espeak, _ := exec.LookPath("espeak-ng")
	sox, _ := exec.LookPath("sox")
	return &promptSynthesizer{root: root, voice: voice, rate: rate, espeak: espeak, sox: sox}
}

func (p *promptSynthesizer) Available() bool {
	return p != nil && p.espeak != "" && p.sox != ""
}

func normalizeAnswerPromptText(value string) (string, error) {
	value = strings.Join(strings.Fields(strings.TrimSpace(value)), " ")
	if value == "" {
		return "", nil
	}
	if !utf8.ValidString(value) {
		return "", errors.New("prompt must be valid text")
	}
	if utf8.RuneCountInString(value) > maxAnswerPromptRunes {
		return "", fmt.Errorf("prompt must be %d characters or fewer", maxAnswerPromptRunes)
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return "", errors.New("prompt contains unsupported control characters")
		}
	}
	return value, nil
}

// Generate creates an 8 kHz mono WAV atomically and returns its extensionless
// Asterisk sound name. Identical text for an endpoint is served from cache.
func (p *promptSynthesizer) Generate(ctx context.Context, accountID, endpointID, text string) (string, error) {
	if text == "" {
		return "", nil
	}
	if p.espeak == "" || p.sox == "" {
		return "", errPromptTTSEngineUnavailable
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	accountHash := shortPromptHash(accountID, 16)
	endpointHash := shortPromptHash(endpointID, 16)
	textHash := shortPromptHash(p.voice+"\x00"+p.rate+"\x00"+text, 20)
	dir := filepath.Join(p.root, accountHash)
	base := "endpoint_" + endpointHash + "_" + textHash
	finalPath := filepath.Join(dir, base+".wav")
	soundName := filepath.ToSlash(filepath.Join("simson", accountHash, base))

	if info, err := os.Stat(finalPath); err == nil && info.Size() > 44 {
		return soundName, nil
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("%w: create prompt cache: %v", errPromptStorageUnavailable, err)
	}

	rawFile, err := os.CreateTemp(dir, ".speech-*.wav")
	if err != nil {
		return "", fmt.Errorf("%w: create speech temporary file: %v", errPromptStorageUnavailable, err)
	}
	rawPath := rawFile.Name()
	if err := rawFile.Close(); err != nil {
		return "", fmt.Errorf("close speech temporary file: %w", err)
	}
	convertedFile, err := os.CreateTemp(dir, ".prompt-*.wav")
	if err != nil {
		_ = os.Remove(rawPath)
		return "", fmt.Errorf("%w: create prompt temporary file: %v", errPromptStorageUnavailable, err)
	}
	convertedPath := convertedFile.Name()
	_ = convertedFile.Close()
	_ = os.Remove(convertedPath)
	defer os.Remove(rawPath)
	defer os.Remove(convertedPath)

	commandCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	if output, err := exec.CommandContext(
		commandCtx, p.espeak, "-v", p.voice, "-s", p.rate, "-w", rawPath, "--", text,
	).CombinedOutput(); err != nil {
		return "", fmt.Errorf("generate speech: %w: %s", err, clippedCommandOutput(output))
	}
	if output, err := exec.CommandContext(
		commandCtx, p.sox, rawPath, "-r", "8000", "-c", "1", "-e", "signed-integer", "-b", "16", convertedPath,
	).CombinedOutput(); err != nil {
		return "", fmt.Errorf("convert speech for Asterisk: %w: %s", err, clippedCommandOutput(output))
	}
	if err := os.Chmod(convertedPath, 0o644); err != nil {
		return "", fmt.Errorf("%w: set prompt permissions: %v", errPromptStorageUnavailable, err)
	}
	if err := os.Rename(convertedPath, finalPath); err != nil {
		return "", fmt.Errorf("%w: publish prompt atomically: %v", errPromptStorageUnavailable, err)
	}
	return soundName, nil
}

// CleanupEndpoint removes obsolete cached prompts only after the database has
// committed the new sound. It never touches another account or endpoint.
func (p *promptSynthesizer) CleanupEndpoint(accountID, endpointID, keepSound string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	dir := filepath.Join(p.root, shortPromptHash(accountID, 16))
	pattern := filepath.Join(dir, "endpoint_"+shortPromptHash(endpointID, 16)+"_*.wav")
	paths, _ := filepath.Glob(pattern)
	keepBase := filepath.Base(strings.TrimSpace(keepSound)) + ".wav"
	for _, path := range paths {
		if keepSound != "" && filepath.Base(path) == keepBase {
			continue
		}
		_ = os.Remove(path)
	}
}

func shortPromptHash(value string, length int) string {
	sum := sha256.Sum256([]byte(value))
	encoded := hex.EncodeToString(sum[:])
	if length > len(encoded) {
		return encoded
	}
	return encoded[:length]
}

func clippedCommandOutput(output []byte) string {
	value := strings.TrimSpace(string(output))
	if len(value) > 300 {
		return value[:300]
	}
	return value
}

func (a *API) writePromptTTSError(w http.ResponseWriter, err error) {
	a.log.Error("generate SIP receiving-phone prompt", map[string]any{"err": err.Error()})
	if errors.Is(err, errPromptTTSEngineUnavailable) {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"error": "prompt speech generation is not installed on the VPS; install espeak-ng and sox",
		})
		return
	}
	if errors.Is(err, errPromptStorageUnavailable) {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"error": "receiving-phone prompt storage is unavailable on the VPS; check the simson service write-path configuration",
		})
		return
	}
	writeJSON(w, http.StatusInternalServerError, map[string]any{
		"error": "could not generate the receiving-phone prompt",
	})
}
