package ratelimit

import (
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// Limiter provides per-key rate limiting.
type Limiter struct {
	mu       sync.RWMutex
	limiters map[string]*entry
	rps      int
	burst    int
}

type entry struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// New creates a rate limiter. rps = requests per second, burst = burst capacity.
func New(rps, burst int) *Limiter {
	return &Limiter{
		limiters: make(map[string]*entry),
		rps:      rps,
		burst:    burst,
	}
}

// Allow checks if a request from the given key is allowed.
func (l *Limiter) Allow(key string) bool {
	l.mu.Lock()
	e, ok := l.limiters[key]
	if !ok {
		e = &entry{
			limiter: rate.NewLimiter(rate.Limit(l.rps), l.burst),
		}
		l.limiters[key] = e
	}
	e.lastSeen = time.Now()
	l.mu.Unlock()
	return e.limiter.Allow()
}

// Cleanup removes limiters that haven't been seen in the given duration.
func (l *Limiter) Cleanup(stale time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	cutoff := time.Now().Add(-stale)
	for key, e := range l.limiters {
		if e.lastSeen.Before(cutoff) {
			delete(l.limiters, key)
		}
	}
}
