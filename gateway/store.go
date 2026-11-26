package gateway

import (
	"sync"
	"sync/atomic"
)

// Store publishes immutable routing snapshots atomically. Connections read the
// snapshot once at accept time; a later reload never changes that connection's
// decision or certificate.
type Store struct {
	current  atomic.Pointer[Snapshot]
	mu       sync.Mutex
	sequence uint64
}

// NewStore creates a store publishing snapshot as generation 1.
func NewStore(snapshot *Snapshot) *Store {
	store := &Store{}
	store.Set(snapshot)
	return store
}

// Current returns the currently published snapshot. The returned value must be
// treated as read-only.
func (s *Store) Current() *Snapshot {
	if s == nil {
		return nil
	}
	return s.current.Load()
}

// Set publishes snapshot, assigns it the next generation, and returns that
// generation. Existing snapshot values remain immutable.
func (s *Store) Set(snapshot *Snapshot) uint64 {
	if s == nil || snapshot == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sequence++
	snapshot.generation = s.sequence
	s.current.Store(snapshot)
	return s.sequence
}
