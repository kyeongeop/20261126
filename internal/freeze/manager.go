// Package freeze implements emergency directory freeze state for the
// team file-sharing service. Freezing never deletes data: it only records
// deny state, which the HTTP layer consults before serving any read.
package freeze

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"sort"
	"strings"
	"sync"
	"time"
)

var (
	ErrAlreadyFrozen     = errors.New("path is already frozen")
	ErrNotFrozen         = errors.New("path is not frozen")
	ErrReasonRequired    = errors.New("reason is required")
	ErrRequestNotFound   = errors.New("unfreeze request not found")
	ErrRequestNotPending = errors.New("unfreeze request is not pending")
	ErrPendingExists     = errors.New("a pending unfreeze request already exists for this freeze")
)

// Freeze describes one active directory freeze.
type Freeze struct {
	Path      string    `json:"path"`
	Reason    string    `json:"reason"`
	ActorID   string    `json:"actorId"`
	FrozenAt  time.Time `json:"frozenAt"`
	RequestID string    `json:"requestId,omitempty"`
}

// UnfreezeRequest is the two-step unfreeze workflow record. An admin must
// create it (with a reason) and another confirmation step must approve it.
type UnfreezeRequest struct {
	ID        string    `json:"id"`
	Path      string    `json:"path"`
	Reason    string    `json:"reason"`
	ActorID   string    `json:"actorId"`
	CreatedAt time.Time `json:"createdAt"`
	Status    string    `json:"status"` // pending | approved
	DecidedBy string    `json:"decidedBy,omitempty"`
	DecidedAt time.Time `json:"decidedAt,omitempty"`
}

// DeniedEvent is one blocked access attempt recorded during a freeze.
type DeniedEvent struct {
	Time      time.Time `json:"time"`
	Path      string    `json:"path"`
	Matched   string    `json:"matchedFrozenPath"`
	Action    string    `json:"action"`
	ActorID   string    `json:"actorId"`
	ActorRole string    `json:"actorRole"`
}

// AuditEntry is a state-changing administrative action.
type AuditEntry struct {
	Time   time.Time `json:"time"`
	Action string    `json:"action"`
	Path   string    `json:"path"`
	Actor  string    `json:"actor"`
	Detail string    `json:"detail,omitempty"`
}

type persisted struct {
	Freezes  map[string]*Freeze          `json:"freezes"`
	Requests map[string]*UnfreezeRequest `json:"requests"`
	Counter  int                         `json:"counter"`
}

// Manager owns freeze state. All state is kept in files under StateDir so
// that a restart never loses an active freeze; the shared data directory is
// never modified or deleted by this package.
type Manager struct {
	stateDir   string
	statePath  string
	deniedPath string
	auditPath  string

	mu   sync.RWMutex
	data persisted
}

// NewManager loads (or initializes) freeze state from stateDir.
func NewManager(stateDir string) (*Manager, error) {
	if err := os.MkdirAll(stateDir, 0o750); err != nil {
		return nil, fmt.Errorf("create state dir: %w", err)
	}
	m := &Manager{
		stateDir:   stateDir,
		statePath:  path.Join(stateDir, "freeze-state.json"),
		deniedPath: path.Join(stateDir, "denied-access.jsonl"),
		auditPath:  path.Join(stateDir, "audit.jsonl"),
		data: persisted{
			Freezes:  map[string]*Freeze{},
			Requests: map[string]*UnfreezeRequest{},
		},
	}
	if err := m.load(); err != nil {
		return nil, err
	}
	return m, nil
}

// Canonical cleans a share-relative path to a stable "/"-separated form.
func Canonical(p string) string {
	p = strings.TrimSpace(p)
	if p == "" || p == "." {
		return "/"
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	c := path.Clean(p)
	if c == "." || !strings.HasPrefix(c, "/") {
		c = "/" + c
	}
	return c
}

func (m *Manager) load() error {
	raw, err := os.ReadFile(m.statePath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read freeze state: %w", err)
	}
	if len(raw) == 0 {
		return nil
	}
	var p persisted
	if err := json.Unmarshal(raw, &p); err != nil {
		return fmt.Errorf("parse freeze state: %w", err)
	}
	if p.Freezes == nil {
		p.Freezes = map[string]*Freeze{}
	}
	if p.Requests == nil {
		p.Requests = map[string]*UnfreezeRequest{}
	}
	m.data = p
	return nil
}

// persist writes state atomically (temp file + rename) so a crash can never
// leave a half-written freeze state behind. Caller must hold m.mu.
func (m *Manager) persist() error {
	raw, err := json.MarshalIndent(m.data, "", "  ")
	if err != nil {
		return err
	}
	tmp := m.statePath + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return fmt.Errorf("write freeze state: %w", err)
	}
	if err := os.Rename(tmp, m.statePath); err != nil {
		return fmt.Errorf("commit freeze state: %w", err)
	}
	return nil
}

// Lookup returns the active freeze governing p, or nil if p is readable.
// A freeze on a parent directory covers every path beneath it.
func (m *Manager) Lookup(p string) *Freeze {
	p = Canonical(p)
	m.mu.RLock()
	defer m.mu.RUnlock()

	best := ""
	for fp := range m.data.Freezes {
		if fp == p || strings.HasPrefix(p, fp+"/") {
			if len(fp) > len(best) {
				best = fp
			}
		}
	}
	if best == "" {
		return nil
	}
	cp := *m.data.Freezes[best]
	return &cp
}

// Freeze marks a directory (and everything below it) frozen. It creates no
// changes inside the shared directory itself.
func (m *Manager) Freeze(p, reason, actorID string) (*Freeze, error) {
	if strings.TrimSpace(reason) == "" {
		return nil, ErrReasonRequired
	}
	p = Canonical(p)

	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.data.Freezes[p]; ok {
		return nil, ErrAlreadyFrozen
	}
	f := &Freeze{
		Path:     p,
		Reason:   strings.TrimSpace(reason),
		ActorID:  actorID,
		FrozenAt: time.Now().UTC(),
	}
	m.data.Freezes[p] = f
	if err := m.persist(); err != nil {
		delete(m.data.Freezes, p)
		return nil, err
	}
	m.appendAudit(AuditEntry{
		Time:   time.Now().UTC(),
		Action: "freeze",
		Path:   p,
		Actor:  actorID,
		Detail: f.Reason,
	})
	cp := *f
	return &cp, nil
}

// RequestUnfreeze opens a pending unfreeze request. A reason is mandatory
// and only one pending request may exist per frozen path.
func (m *Manager) RequestUnfreeze(p, reason, actorID string) (*UnfreezeRequest, error) {
	if strings.TrimSpace(reason) == "" {
		return nil, ErrReasonRequired
	}
	p = Canonical(p)

	m.mu.Lock()
	defer m.mu.Unlock()
	f, ok := m.data.Freezes[p]
	if !ok {
		return nil, ErrNotFrozen
	}
	if f.RequestID != "" {
		if req, ok := m.data.Requests[f.RequestID]; ok && req.Status == "pending" {
			return nil, ErrPendingExists
		}
	}
	m.data.Counter++
	req := &UnfreezeRequest{
		ID:        fmt.Sprintf("UR-%04d", m.data.Counter),
		Path:      p,
		Reason:    strings.TrimSpace(reason),
		ActorID:   actorID,
		CreatedAt: time.Now().UTC(),
		Status:    "pending",
	}
	m.data.Requests[req.ID] = req
	f.RequestID = req.ID
	if err := m.persist(); err != nil {
		m.data.Counter--
		delete(m.data.Requests, req.ID)
		f.RequestID = ""
		return nil, err
	}
	m.appendAudit(AuditEntry{
		Time:   time.Now().UTC(),
		Action: "unfreeze-request",
		Path:   p,
		Actor:  actorID,
		Detail: req.ID + ": " + req.Reason,
	})
	cp := *req
	return &cp, nil
}

// ConfirmUnfreeze is the administrator confirmation step. It removes the
// freeze only after a pending request has been explicitly approved.
func (m *Manager) ConfirmUnfreeze(requestID, adminID string) (*Freeze, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	req, ok := m.data.Requests[requestID]
	if !ok {
		return nil, ErrRequestNotFound
	}
	if req.Status != "pending" {
		return nil, ErrRequestNotPending
	}
	f, ok := m.data.Freezes[req.Path]
	if !ok {
		return nil, ErrNotFrozen
	}

	req.Status = "approved"
	req.DecidedBy = adminID
	req.DecidedAt = time.Now().UTC()
	delete(m.data.Freezes, req.Path)
	f.RequestID = ""
	if err := m.persist(); err != nil {
		// Roll back the in-memory change on persistence failure.
		m.data.Freezes[req.Path] = f
		req.Status = "pending"
		req.DecidedBy = ""
		req.DecidedAt = time.Time{}
		return nil, err
	}
	m.appendAudit(AuditEntry{
		Time:   time.Now().UTC(),
		Action: "unfreeze-confirm",
		Path:   req.Path,
		Actor:  adminID,
		Detail: req.ID,
	})
	cp := *f
	return &cp, nil
}

// ListFreezes returns all active freezes sorted by path.
func (m *Manager) ListFreezes() []Freeze {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]Freeze, 0, len(m.data.Freezes))
	for _, f := range m.data.Freezes {
		out = append(out, *f)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

// ListRequests returns unfreeze requests, newest first.
func (m *Manager) ListRequests() []UnfreezeRequest {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]UnfreezeRequest, 0, len(m.data.Requests))
	for _, r := range m.data.Requests {
		out = append(out, *r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out
}

var logMu sync.Mutex

func appendJSONLine(filePath string, v any) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	logMu.Lock()
	defer logMu.Unlock()
	f, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(raw)
	return err
}

// appendAudit must be called while holding m.mu so audit order matches the
// state changes that produced them.
func (m *Manager) appendAudit(e AuditEntry) {
	if err := appendJSONLine(m.auditPath, e); err != nil {
		fmt.Fprintf(os.Stderr, "freeze: write audit log: %v\n", err)
	}
}

// RecordDenied appends one blocked access attempt to the denied-access log.
// This runs on every rejected read while a freeze is active.
func (m *Manager) RecordDenied(e DeniedEvent) {
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	if err := appendJSONLine(m.deniedPath, e); err != nil {
		fmt.Fprintf(os.Stderr, "freeze: write denied-access log: %v\n", err)
	}
}

func readJSONLines[T any](filePath string) ([]T, error) {
	raw, err := os.ReadFile(filePath)
	if errors.Is(err, os.ErrNotExist) {
		return []T{}, nil
	}
	if err != nil {
		return nil, err
	}
	var out []T
	for _, line := range strings.Split(strings.TrimRight(string(raw), "\n"), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var v T
		if err := json.Unmarshal([]byte(line), &v); err != nil {
			return nil, fmt.Errorf("corrupt log line: %w", err)
		}
		out = append(out, v)
	}
	return out, nil
}

// DeniedEvents returns all recorded blocked access attempts, oldest first.
func (m *Manager) DeniedEvents() ([]DeniedEvent, error) {
	return readJSONLines[DeniedEvent](m.deniedPath)
}

// AuditLog returns the administrative audit trail, oldest first.
func (m *Manager) AuditLog() ([]AuditEntry, error) {
	return readJSONLines[AuditEntry](m.auditPath)
}
