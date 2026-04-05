package protocol

import "time"

// Protocol version — increment on breaking changes.
const ProtocolVersion = "1.0.0"

// --- Envelope ---

// Envelope wraps every message on the wire.
type Envelope struct {
	Type      string    `json:"type"`
	ID        string    `json:"id"`                  // unique message ID (UUID)
	Timestamp time.Time `json:"ts"`                  // sender wall-clock
	Nonce     string    `json:"nonce,omitempty"`      // replay prevention
	Signature string    `json:"signature,omitempty"`  // HMAC-SHA256 hex
	Payload   any       `json:"payload"`              // type-specific body
}

// --- Auth ---

type HelloPayload struct {
	NodeID          string   `json:"node_id"`
	AccountID       string   `json:"account_id"`
	InstallToken    string   `json:"install_token"`
	AddonVersion    string   `json:"addon_version"`
	ProtocolVersion string   `json:"protocol_version"`
	Capabilities    []string `json:"capabilities"` // e.g. ["haos","asterisk","voice"]
	Fingerprint     string   `json:"fingerprint,omitempty"`
}

type AuthResultPayload struct {
	OK              bool   `json:"ok"`
	Reason          string `json:"reason,omitempty"`
	ServerVersion   string `json:"server_version"`
	ProtocolVersion string `json:"protocol_version"`
	HeartbeatSec    int    `json:"heartbeat_sec"`
}

// --- Heartbeat ---

type HeartbeatPayload struct {
	NodeID string `json:"node_id"`
}

type HeartbeatAckPayload struct {
	ServerTime time.Time `json:"server_time"`
}

// --- Call lifecycle ---

type CallRequestPayload struct {
	CallID       string            `json:"call_id"`
	FromNodeID   string            `json:"from_node_id"`
	ToNodeID     string            `json:"to_node_id"`
	CallType     string            `json:"call_type"` // "voice", "intercom", "sip"
	Metadata     map[string]string `json:"metadata,omitempty"`
}

type CallInvitePayload struct {
	CallID       string            `json:"call_id"`
	FromNodeID   string            `json:"from_node_id"`
	FromLabel    string            `json:"from_label"`
	CallType     string            `json:"call_type"`
	Metadata     map[string]string `json:"metadata,omitempty"`
}

type CallAcceptPayload struct {
	CallID string `json:"call_id"`
	NodeID string `json:"node_id"`
}

type CallRejectPayload struct {
	CallID string `json:"call_id"`
	NodeID string `json:"node_id"`
	Reason string `json:"reason,omitempty"`
}

type CallEndPayload struct {
	CallID string `json:"call_id"`
	NodeID string `json:"node_id"`
	Reason string `json:"reason,omitempty"` // "hangup", "timeout", "error"
}

type CallStatusPayload struct {
	CallID string `json:"call_id"`
	Status string `json:"status"` // "ringing","active","ended","failed"
	Reason string `json:"reason,omitempty"`
}

// --- Error ---

type ErrorPayload struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Ref     string `json:"ref,omitempty"` // message ID this error relates to
}

// --- WebRTC signaling ---

type WebRTCSignalPayload struct {
	CallID       string `json:"call_id"`
	FromNodeID   string `json:"from_node_id"`
	ToNodeID     string `json:"to_node_id"`
	SignalType   string `json:"signal_type"` // "offer", "answer", "ice-candidate"
	Data         any    `json:"data"`        // SDP or ICE candidate object
}

// --- User presence ---

type UserPresenceEntry struct {
	UserID   string `json:"user_id"`
	UserName string `json:"user_name"`
}

type UsersUpdatePayload struct {
	NodeID string               `json:"node_id"`
	Users  []UserPresenceEntry  `json:"users"`
}

type UsersQueryPayload struct {
	TargetNodeID string `json:"target_node_id"`
}

type UsersListPayload struct {
	NodeID string               `json:"node_id"`
	Users  []UserPresenceEntry  `json:"users"`
	Ref    string               `json:"ref,omitempty"` // message ID this responds to
}

// --- Message types ---

const (
	TypeHello      = "hello"
	TypeAuthResult = "auth.result"
	TypeHeartbeat  = "heartbeat"
	TypeHeartbeatAck = "heartbeat.ack"

	TypeCallRequest = "call.request"
	TypeCallInvite  = "call.invite"
	TypeCallAccept  = "call.accept"
	TypeCallReject  = "call.reject"
	TypeCallEnd     = "call.end"
	TypeCallStatus  = "call.status"

	TypeWebRTCSignal = "webrtc.signal"

	TypeUsersUpdate = "users.update"
	TypeUsersQuery  = "users.query"
	TypeUsersList   = "users.list"

	TypeError = "error"
)

// --- Error codes ---

const (
	ErrCodeBadRequest     = 4000
	ErrCodeUnauthorized   = 4001
	ErrCodeForbidden      = 4003
	ErrCodeNodeOffline    = 4004
	ErrCodeRateLimited    = 4029
	ErrCodeInternal       = 5000
	ErrCodeNotFound       = 4040
	ErrCodeCallTimeout    = 4008
	ErrCodeLimitExceeded  = 4009
	ErrCodeVersionMismatch = 4010
)
