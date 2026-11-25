// Package ratelimit implements anti-guessing throttling for password
// protected share links.
//
// Limits are tracked per (share, request source) pair using two independent
// mechanisms:
//
//   - A sliding-start fixed window: at most MaxAttemptsPerWindow attempts may
//     be made within Window. Exceeding the quota locks the pair for Lockout.
//   - Consecutive failures: reaching MaxConsecutiveFailures failed attempts in
//     a row locks the pair for Lockout, even when the window quota is not
//     exhausted.
//
// The state is plain data so it can be JSON-persisted and survive restarts.
package ratelimit

import (
	"errors"
	"time"
)

// Config holds the throttling parameters.
type Config struct {
	// MaxAttemptsPerWindow is the maximum number of attempts allowed inside
	// one rolling window before a lock is engaged.
	MaxAttemptsPerWindow int
	// Window is the length of the fixed counting window.
	Window time.Duration
	// MaxConsecutiveFailures is the number of back-to-back failed attempts
	// that triggers a lock.
	MaxConsecutiveFailures int
	// Lockout is how long a pair stays locked after a limit is breached.
	Lockout time.Duration
}

// DefaultConfig returns conservative defaults suitable for a small team
// deployment: 5 attempts per 10 minute window and a 5 minute lock after
// either 5 windowed attempts or 5 consecutive failures.
func DefaultConfig() Config {
	return Config{
		MaxAttemptsPerWindow:   5,
		Window:                 10 * time.Minute,
		MaxConsecutiveFailures: 5,
		Lockout:                5 * time.Minute,
	}
}

// State is the persisted throttling document.
type State struct {
	Entries map[string]Entry `json:"entries"`
}

// Entry tracks one (share, source) pair.
type Entry struct {
	WindowStart         time.Time `json:"window_start"`
	WindowAttempts      int       `json:"window_attempts"`
	ConsecutiveFailures int       `json:"consecutive_failures"`
	LockedUntil         time.Time `json:"locked_until"`
}

// ErrLocked indicates the pair is currently locked. It carries the remaining
// lock duration so callers can set a Retry-After header.
var ErrLocked = errors.New("ratelimit: source is temporarily locked")

// LockError wraps ErrLocked with the time remaining on the lock.
type LockError struct {
	RetryAfter time.Duration
}

func (e *LockError) Error() string { return ErrLocked.Error() }
func (e *LockError) Unwrap() error { return ErrLocked }

// Limiter enforces a Config against a State.
type Limiter struct {
	cfg Config
	now func() time.Time
}

// New builds a Limiter. A nil clock defaults to time.Now.
func New(cfg Config, now func() time.Time) *Limiter {
	if now == nil {
		now = time.Now
	}
	return &Limiter{cfg: cfg, now: now}
}

// NewState returns an initialized empty state document.
func NewState() State {
	return State{Entries: map[string]Entry{}}
}

// Key builds the map key for a share/source pair. The NUL separator cannot
// appear in a share ID or a cleaned source identifier.
func Key(shareID, source string) string {
	return shareID + "\x00" + source
}

// BeginRequest is invoked once per verification attempt. It refreshes the
// counting window, rejects locked pairs without consuming any quota, and
// otherwise records the attempt and engages a lock when the window quota is
// exceeded. It mutates state in place; the caller is responsible for
// persisting.
func (l *Limiter) BeginRequest(state *State, key string) error {
	if state.Entries == nil {
		state.Entries = map[string]Entry{}
	}
	now := l.now()
	entry := state.Entries[key]

	if !entry.LockedUntil.IsZero() && entry.LockedUntil.After(now) {
		return &LockError{RetryAfter: entry.LockedUntil.Sub(now)}
	}
	hadLock := !entry.LockedUntil.IsZero()
	// An expired lock is cleared before normal window handling.
	entry.LockedUntil = time.Time{}

	if hadLock || entry.WindowStart.IsZero() || now.Sub(entry.WindowStart) >= l.cfg.Window {
		// A new window clears the consecutive-failure history as well:
		// failures from an old window (or from the period before a lock)
		// must not lock a source again once it is allowed back in.
		entry.WindowStart = now
		entry.WindowAttempts = 0
		entry.ConsecutiveFailures = 0
	}
	if entry.WindowAttempts >= l.cfg.MaxAttemptsPerWindow {
		// The window quota is exhausted: this attempt is refused and the
		// pair is locked instead of being counted.
		entry.LockedUntil = now.Add(l.cfg.Lockout)
		state.Entries[key] = entry
		return &LockError{RetryAfter: l.cfg.Lockout}
	}
	entry.WindowAttempts++
	state.Entries[key] = entry
	return nil
}

// RecordResult updates counters after a verification attempt. A success
// clears all counters for the pair; a failure increments the consecutive
// failure counter and locks when the threshold is reached.
func (l *Limiter) RecordResult(state *State, key string, success bool) {
	now := l.now()
	entry := state.Entries[key]

	if success {
		delete(state.Entries, key)
		return
	}

	entry.ConsecutiveFailures++
	if entry.ConsecutiveFailures >= l.cfg.MaxConsecutiveFailures {
		entry.LockedUntil = now.Add(l.cfg.Lockout)
	}
	state.Entries[key] = entry
}

// Sweep removes entries that no longer carry any state: an expired window,
// no active lock and no consecutive failure history. It bounds the size of
// the persisted document.
func (l *Limiter) Sweep(state *State) {
	now := l.now()
	for key, entry := range state.Entries {
		lockActive := entry.LockedUntil.After(now)
		windowActive := !entry.WindowStart.IsZero() &&
			now.Sub(entry.WindowStart) < l.cfg.Window
		if !lockActive && !windowActive {
			delete(state.Entries, key)
		}
	}
}
