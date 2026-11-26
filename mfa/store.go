package mfa

import (
	"sync"
	"time"
)

// Clock allows tests to control time deterministically.
type Clock func() time.Time

// Store is the persistence boundary of the workflow. The shipped
// implementation is in-memory so the package needs no external database.
type Store interface {
	CreateUser(user User)
	GetUser(id string) (User, bool)
	UpdateUser(user User)

	CreateApp(app App)
	GetApp(id string) (App, bool)

	CreateRequest(req ResetRequest)
	UpdateRequest(req ResetRequest)
	GetRequest(id string) (ResetRequest, bool)
	ListRequestsByUser(userID string) []ResetRequest
	ListRequests() []ResetRequest

	AppendAudit(event AuditEvent)
	AuditTrail() []AuditEvent
}

// MemoryStore is a goroutine-safe in-memory Store.
type MemoryStore struct {
	mu       sync.RWMutex
	users    map[string]User
	apps     map[string]App
	requests map[string]ResetRequest
	audit    []AuditEvent
}

// NewMemoryStore builds an empty in-memory store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		users:    make(map[string]User),
		apps:     make(map[string]App),
		requests: make(map[string]ResetRequest),
	}
}

// CreateUser inserts a user.
func (s *MemoryStore) CreateUser(user User) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.users[user.ID] = user
}

// GetUser returns the user with id.
func (s *MemoryStore) GetUser(id string) (User, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	user, ok := s.users[id]
	return user, ok
}

// UpdateUser replaces a stored user.
func (s *MemoryStore) UpdateUser(user User) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.users[user.ID] = user
}

// CreateApp inserts an application.
func (s *MemoryStore) CreateApp(app App) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.apps[app.ID] = app
}

// GetApp returns the application with id.
func (s *MemoryStore) GetApp(id string) (App, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	app, ok := s.apps[id]
	return app, ok
}

// CreateRequest inserts a reset request.
func (s *MemoryStore) CreateRequest(req ResetRequest) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requests[req.ID] = req
}

// UpdateRequest replaces a stored reset request.
func (s *MemoryStore) UpdateRequest(req ResetRequest) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requests[req.ID] = req
}

// GetRequest returns the request with id.
func (s *MemoryStore) GetRequest(id string) (ResetRequest, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	req, ok := s.requests[id]
	return req, ok
}

// ListRequestsByUser returns the user's requests ordered by creation time.
func (s *MemoryStore) ListRequestsByUser(userID string) []ResetRequest {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []ResetRequest
	for _, req := range s.requests {
		if req.UserID == userID {
			out = append(out, req)
		}
	}
	sortRequests(out)
	return out
}

// ListRequests returns every request ordered by creation time.
func (s *MemoryStore) ListRequests() []ResetRequest {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]ResetRequest, 0, len(s.requests))
	for _, req := range s.requests {
		out = append(out, req)
	}
	sortRequests(out)
	return out
}

// AppendAudit records an audit event.
func (s *MemoryStore) AppendAudit(event AuditEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.audit = append(s.audit, event)
}

// AuditTrail returns a copy of the audit events in append order.
func (s *MemoryStore) AuditTrail() []AuditEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]AuditEvent, len(s.audit))
	copy(out, s.audit)
	return out
}

func sortRequests(reqs []ResetRequest) {
	for i := 1; i < len(reqs); i++ {
		for j := i; j > 0 && reqs[j-1].CreatedAt.After(reqs[j].CreatedAt); j++ {
			reqs[j-1], reqs[j] = reqs[j], reqs[j-1]
		}
	}
}
