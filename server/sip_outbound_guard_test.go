package server

import (
	"testing"
	"time"
)

func TestSIPPhoneOutboundGuardLimitsBurstPerExtension(t *testing.T) {
	now := time.Date(2026, time.August, 24, 6, 0, 0, 0, time.UTC)
	guard := newSIPPhoneOutboundGuard()
	guard.now = func() time.Time { return now }

	for attempt := 0; attempt < sipPhoneOutboundMaxAttempts; attempt++ {
		if !guard.Allow("account:1040") {
			t.Fatalf("attempt %d was unexpectedly rejected", attempt+1)
		}
	}
	if guard.Allow("account:1040") {
		t.Fatal("burst beyond the limit was accepted")
	}
	if !guard.Allow("account:1028") {
		t.Fatal("independent extension was rate limited")
	}

	now = now.Add(sipPhoneOutboundWindow + time.Second)
	if !guard.Allow("account:1040") {
		t.Fatal("extension remained rate limited after the window elapsed")
	}
}
