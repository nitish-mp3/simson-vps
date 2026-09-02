package server

import (
	"sync"
	"time"
)

const (
	sipPhoneOutboundWindow      = time.Minute
	sipPhoneOutboundMaxAttempts = 5
)

type sipPhoneOutboundGuard struct {
	mu       sync.Mutex
	attempts map[string][]time.Time
	now      func() time.Time
}

func newSIPPhoneOutboundGuard() *sipPhoneOutboundGuard {
	return &sipPhoneOutboundGuard{
		attempts: make(map[string][]time.Time),
		now:      time.Now,
	}
}

func (g *sipPhoneOutboundGuard) Allow(key string) bool {
	if g == nil || key == "" {
		return false
	}

	now := g.now()
	cutoff := now.Add(-sipPhoneOutboundWindow)

	g.mu.Lock()
	defer g.mu.Unlock()

	recent := g.attempts[key]
	kept := recent[:0]
	for _, attemptedAt := range recent {
		if attemptedAt.After(cutoff) {
			kept = append(kept, attemptedAt)
		}
	}
	if len(kept) >= sipPhoneOutboundMaxAttempts {
		g.attempts[key] = kept
		return false
	}
	g.attempts[key] = append(kept, now)
	return true
}
