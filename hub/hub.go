package hub

import (
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// Session represents a single connected node.
type Session struct {
	mu           sync.Mutex
	Conn         *websocket.Conn
	NodeID       string
	AccountID    string
	Capabilities []string
	AddonVersion string
	RemoteIP     string
	ConnectedAt  time.Time
	LastSeen     time.Time
}

// Send writes a message to the WebSocket. Thread-safe.
func (s *Session) Send(data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	return s.Conn.WriteMessage(websocket.TextMessage, data)
}

// Touch updates last-seen.
func (s *Session) Touch() {
	s.mu.Lock()
	s.LastSeen = time.Now().UTC()
	s.mu.Unlock()
}

// Hub maintains live node sessions.
type Hub struct {
	mu       sync.RWMutex
	sessions map[string]*Session // nodeID -> session
}

// New creates an empty Hub.
func New() *Hub {
	return &Hub{
		sessions: make(map[string]*Session),
	}
}

// Register adds or replaces a node session.
func (h *Hub) Register(s *Session) {
	h.mu.Lock()
	defer h.mu.Unlock()

	// If there's an existing session for this node, close it (stale connection).
	if old, ok := h.sessions[s.NodeID]; ok {
		old.Conn.Close()
	}
	h.sessions[s.NodeID] = s
}

// Unregister removes a session if it matches the given connection.
func (h *Hub) Unregister(nodeID string, conn *websocket.Conn) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if s, ok := h.sessions[nodeID]; ok && s.Conn == conn {
		delete(h.sessions, nodeID)
	}
}

// Get returns the session for a node, or nil.
func (h *Hub) Get(nodeID string) *Session {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.sessions[nodeID]
}

// IsOnline checks if a node has an active session.
func (h *Hub) IsOnline(nodeID string) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	_, ok := h.sessions[nodeID]
	return ok
}

// ListAll returns a snapshot of all sessions.
func (h *Hub) ListAll() []*Session {
	h.mu.RLock()
	defer h.mu.RUnlock()
	out := make([]*Session, 0, len(h.sessions))
	for _, s := range h.sessions {
		out = append(out, s)
	}
	return out
}

// ListByAccount returns sessions belonging to one account.
func (h *Hub) ListByAccount(accountID string) []*Session {
	h.mu.RLock()
	defer h.mu.RUnlock()
	var out []*Session
	for _, s := range h.sessions {
		if s.AccountID == accountID {
			out = append(out, s)
		}
	}
	return out
}

// Count returns total connected nodes.
func (h *Hub) Count() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.sessions)
}

// CountByAccount returns connected nodes for one account.
func (h *Hub) CountByAccount(accountID string) int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	count := 0
	for _, s := range h.sessions {
		if s.AccountID == accountID {
			count++
		}
	}
	return count
}

// SweepStale removes sessions that haven't been seen within the timeout.
func (h *Hub) SweepStale(timeout time.Duration) []string {
	h.mu.Lock()
	cutoff := time.Now().Add(-timeout)
	var stale []*Session
	var removed []string
	for id, s := range h.sessions {
		if s.LastSeen.Before(cutoff) {
			stale = append(stale, s)
			delete(h.sessions, id)
			removed = append(removed, id)
		}
	}
	h.mu.Unlock()

	// Close connections outside the lock to avoid blocking the hub.
	for _, s := range stale {
		s.Conn.Close()
	}
	return removed
}
