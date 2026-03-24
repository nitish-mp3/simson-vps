package protocol

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// NewEnvelope creates a new Envelope with a fresh ID and timestamp.
func NewEnvelope(msgType string, payload any) Envelope {
	return Envelope{
		Type:      msgType,
		ID:        uuid.NewString(),
		Timestamp: time.Now().UTC(),
		Payload:   payload,
	}
}

// Sign computes HMAC-SHA256 over (id + type + nonce + timestamp) with the given secret,
// and populates Nonce + Signature on the envelope.
func (e *Envelope) Sign(secret []byte) error {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("generate nonce: %w", err)
	}
	e.Nonce = hex.EncodeToString(nonce)
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(e.ID + e.Type + e.Nonce + e.Timestamp.Format(time.RFC3339Nano)))
	e.Signature = hex.EncodeToString(mac.Sum(nil))
	return nil
}

// Verify checks envelope HMAC. Returns false if invalid.
func (e *Envelope) Verify(secret []byte) bool {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(e.ID + e.Type + e.Nonce + e.Timestamp.Format(time.RFC3339Nano)))
	expected := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(expected), []byte(e.Signature))
}

// Encode serialises the envelope to JSON.
func (e *Envelope) Encode() ([]byte, error) {
	return json.Marshal(e)
}

// DecodeEnvelope parses a raw JSON message into an Envelope.
func DecodeEnvelope(data []byte) (*Envelope, error) {
	var env Envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, fmt.Errorf("decode envelope: %w", err)
	}
	return &env, nil
}

// DecodePayload unmarshals the Payload field into the target struct.
func DecodePayload[T any](env *Envelope) (*T, error) {
	raw, err := json.Marshal(env.Payload)
	if err != nil {
		return nil, err
	}
	var t T
	if err := json.Unmarshal(raw, &t); err != nil {
		return nil, err
	}
	return &t, nil
}
