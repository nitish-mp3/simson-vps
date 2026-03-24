package calls

import (
	"sync"
	"time"
)

// State is the current state of a call.
type State string

const (
	StateRinging State = "ringing"
	StateActive  State = "active"
	StateEnded   State = "ended"
	StateFailed  State = "failed"
)

// Call tracks a single in-flight call.
type Call struct {
	ID         string
	FromNode   string
	ToNode     string
	AccountID  string
	CallType   string
	State      State
	CreatedAt  time.Time
	AnsweredAt time.Time
	EndedAt    time.Time
	EndReason  string
}

// Manager tracks active calls in memory.
type Manager struct {
	mu    sync.RWMutex
	calls map[string]*Call // callID -> Call
}

// NewManager creates a call manager.
func NewManager() *Manager {
	return &Manager{calls: make(map[string]*Call)}
}

// Create registers a new call as ringing. Returns false if call ID already exists.
func (m *Manager) Create(c *Call) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.calls[c.ID]; exists {
		return false
	}
	c.State = StateRinging
	c.CreatedAt = time.Now().UTC()
	m.calls[c.ID] = c
	return true
}

// Accept transitions a call to active.
func (m *Manager) Accept(callID string) (*Call, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.calls[callID]
	if !ok || c.State != StateRinging {
		return nil, false
	}
	c.State = StateActive
	c.AnsweredAt = time.Now().UTC()
	return c, true
}

// End terminates a call.
func (m *Manager) End(callID, reason string) (*Call, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.calls[callID]
	if !ok {
		return nil, false
	}
	if c.State == StateEnded || c.State == StateFailed {
		return c, false
	}
	if reason == "error" || reason == "timeout" {
		c.State = StateFailed
	} else {
		c.State = StateEnded
	}
	c.EndedAt = time.Now().UTC()
	c.EndReason = reason
	return c, true
}

// Get returns a call by ID.
func (m *Manager) Get(callID string) *Call {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.calls[callID]
}

// ActiveByNode returns all active/ringing calls involving a node.
func (m *Manager) ActiveByNode(nodeID string) []*Call {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []*Call
	for _, c := range m.calls {
		if (c.FromNode == nodeID || c.ToNode == nodeID) && (c.State == StateRinging || c.State == StateActive) {
			out = append(out, c)
		}
	}
	return out
}

// CountActiveByAccount counts active/ringing calls for an account.
func (m *Manager) CountActiveByAccount(accountID string) int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	count := 0
	for _, c := range m.calls {
		if c.AccountID == accountID && (c.State == StateRinging || c.State == StateActive) {
			count++
		}
	}
	return count
}

// SweepExpired ends calls that have been ringing past the timeout.
func (m *Manager) SweepExpired(ringTimeout time.Duration) []*Call {
	m.mu.Lock()
	defer m.mu.Unlock()

	cutoff := time.Now().Add(-ringTimeout)
	var expired []*Call
	for _, c := range m.calls {
		if c.State == StateRinging && c.CreatedAt.Before(cutoff) {
			c.State = StateFailed
			c.EndedAt = time.Now().UTC()
			c.EndReason = "timeout"
			expired = append(expired, c)
		}
	}
	return expired
}

// Cleanup removes ended/failed calls older than the given duration.
func (m *Manager) Cleanup(olderThan time.Duration) int {
	m.mu.Lock()
	defer m.mu.Unlock()

	cutoff := time.Now().Add(-olderThan)
	removed := 0
	for id, c := range m.calls {
		if (c.State == StateEnded || c.State == StateFailed) && c.EndedAt.Before(cutoff) {
			delete(m.calls, id)
			removed++
		}
	}
	return removed
}

// ListAll returns a snapshot of all calls.
func (m *Manager) ListAll() []*Call {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*Call, 0, len(m.calls))
	for _, c := range m.calls {
		out = append(out, c)
	}
	return out
}
