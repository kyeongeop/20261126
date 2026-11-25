package ratelimit

import (
	"errors"
	"testing"
	"time"
)

func testConfig() Config {
	return Config{
		MaxAttemptsPerWindow:   3,
		Window:                 10 * time.Minute,
		MaxConsecutiveFailures: 3,
		Lockout:                5 * time.Minute,
	}
}

type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time          { return c.t }
func (c *fakeClock) advance(d time.Duration) { c.t = c.t.Add(d) }

func isLocked(err error) bool {
	var lockErr *LockError
	return errors.As(err, &lockErr)
}

func newTestLimiter() (*Limiter, *fakeClock) {
	clock := &fakeClock{t: time.Date(2026, 11, 26, 10, 0, 0, 0, time.UTC)}
	return New(testConfig(), clock.now), clock
}

func TestWindowQuotaLocksAfterMaxAttempts(t *testing.T) {
	cfg := testConfig()
	// Isolate the window-quota rule from the consecutive-failure rule.
	cfg.MaxConsecutiveFailures = 100
	clock := &fakeClock{t: time.Date(2026, 11, 26, 10, 0, 0, 0, time.UTC)}
	l := New(cfg, clock.now)
	state := NewState()
	key := Key("share-1", "192.0.2.10")

	// First three attempts consume the window quota.
	for i := 0; i < 3; i++ {
		if err := l.BeginRequest(&state, key); err != nil {
			t.Fatalf("attempt %d: unexpected error: %v", i+1, err)
		}
		l.RecordResult(&state, key, false)
	}

	// The fourth attempt breaches the window quota and is locked.
	err := l.BeginRequest(&state, key)
	if !isLocked(err) {
		t.Fatalf("expected LockError, got %v", err)
	}

	clock.advance(4 * time.Minute)
	err = l.BeginRequest(&state, key)
	if !isLocked(err) {
		t.Fatalf("expected still locked, got %v", err)
	}

	// Advancing past both the lock and the counting window admits a
	// fresh attempt. While the window is still full, retrying at the
	// lock boundary immediately re-locks, which is intended.
	clock.advance(6*time.Minute + time.Second)
	if err := l.BeginRequest(&state, key); err != nil {
		t.Fatalf("expected lock to expire, got %v", err)
	}
}

func TestConsecutiveFailuresTriggerLock(t *testing.T) {
	// With a large window quota, the lock can only come from the
	// consecutive-failure rule.
	cfg := testConfig()
	cfg.MaxAttemptsPerWindow = 100
	clock := &fakeClock{t: time.Date(2026, 11, 26, 10, 0, 0, 0, time.UTC)}
	l := New(cfg, clock.now)
	state := NewState()
	key := Key("share-2", "192.0.2.20")

	for i := 0; i < 2; i++ {
		if err := l.BeginRequest(&state, key); err != nil {
			t.Fatalf("attempt %d: %v", i+1, err)
		}
		l.RecordResult(&state, key, false)
	}

	if err := l.BeginRequest(&state, key); err != nil {
		t.Fatalf("third attempt should be admitted: %v", err)
	}
	l.RecordResult(&state, key, false)

	err := l.BeginRequest(&state, key)
	if !isLocked(err) {
		t.Fatalf("expected lock after 3 consecutive failures, got %v", err)
	}
}

func TestSuccessResetsCounters(t *testing.T) {
	l, clock := newTestLimiter()
	state := NewState()
	key := Key("share-3", "192.0.2.30")

	for i := 0; i < 2; i++ {
		if err := l.BeginRequest(&state, key); err != nil {
			t.Fatal(err)
		}
		l.RecordResult(&state, key, false)
	}
	if err := l.BeginRequest(&state, key); err != nil {
		t.Fatal(err)
	}
	l.RecordResult(&state, key, true)

	if _, ok := state.Entries[key]; ok {
		t.Fatal("successful verification should remove the entry")
	}

	clock.advance(time.Minute)
	for i := 0; i < 3; i++ {
		if err := l.BeginRequest(&state, key); err != nil {
			t.Fatalf("attempt after reset %d: %v", i+1, err)
		}
		l.RecordResult(&state, key, false)
	}
}

func TestWindowRollsOver(t *testing.T) {
	l, clock := newTestLimiter()
	state := NewState()
	key := Key("share-4", "192.0.2.40")

	for i := 0; i < 3; i++ {
		if err := l.BeginRequest(&state, key); err != nil {
			t.Fatal(err)
		}
		l.RecordResult(&state, key, false)
	}

	clock.advance(10 * time.Minute)
	for i := 0; i < 3; i++ {
		if err := l.BeginRequest(&state, key); err != nil {
			t.Fatalf("fresh window attempt %d: %v", i+1, err)
		}
		l.RecordResult(&state, key, false)
	}
}

func TestKeysAreScopedPerShareAndSource(t *testing.T) {
	l, _ := newTestLimiter()
	state := NewState()

	k1 := Key("share-a", "192.0.2.1")
	k2 := Key("share-b", "192.0.2.1")
	k3 := Key("share-a", "192.0.2.2")
	for _, k := range []string{k1, k2, k3} {
		for i := 0; i < 3; i++ {
			if err := l.BeginRequest(&state, k); err != nil {
				t.Fatalf("key %s attempt %d: %v", k, i+1, err)
			}
			l.RecordResult(&state, k, false)
		}
	}
	if err := l.BeginRequest(&state, k1); !isLocked(err) {
		t.Fatalf("k1 should be locked, got %v", err)
	}
	if err := l.BeginRequest(&state, k2); !isLocked(err) {
		t.Fatalf("k2 should be locked independently, got %v", err)
	}
	if err := l.BeginRequest(&state, k3); !isLocked(err) {
		t.Fatalf("k3 should be locked independently, got %v", err)
	}
}

func TestSweepRemovesIdleEntries(t *testing.T) {
	l, clock := newTestLimiter()
	state := NewState()
	key := Key("share-5", "192.0.2.50")

	if err := l.BeginRequest(&state, key); err != nil {
		t.Fatal(err)
	}
	l.RecordResult(&state, key, false)

	clock.advance(11 * time.Minute)
	l.Sweep(&state)
	if _, ok := state.Entries[key]; ok {
		t.Fatal("idle entry with expired window should be swept")
	}
}

func TestSweepKeepsLockedEntries(t *testing.T) {
	l, clock := newTestLimiter()
	state := NewState()
	key := Key("share-6", "192.0.2.60")

	for i := 0; i < 3; i++ {
		_ = l.BeginRequest(&state, key)
		l.RecordResult(&state, key, false)
	}
	_ = l.BeginRequest(&state, key) // engages lock

	l.Sweep(&state)
	if _, ok := state.Entries[key]; !ok {
		t.Fatal("locked entry must not be swept")
	}

	// Once both the lock and the window expire, the entry is prunable.
	clock.advance(20 * time.Minute)
	l.Sweep(&state)
	if _, ok := state.Entries[key]; ok {
		t.Fatal("entry with expired lock and window should be swept")
	}
}
