// Package clock provides a concurrency-safe time source.
//
// Production code uses the zero-value behavior of Now (wall clock); tests can
// install a controlled Clock to deterministically exercise expiry.
package clock

import (
	"sync"
	"time"
)

// Clock is a mutable, goroutine-safe time source.
type Clock struct {
	mu  sync.RWMutex
	now time.Time
}

// New returns a Clock initialized to the current wall-clock time.
func New() *Clock {
	return NewAt(time.Now())
}

// NewAt returns a Clock initialized to t.
func NewAt(t time.Time) *Clock {
	return &Clock{now: t}
}

// Now returns the clock's current time.
func (c *Clock) Now() time.Time {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.now
}

// Set moves the clock to t.
func (c *Clock) Set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = t
}

// Advance moves the clock forward by d.
func (c *Clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}
