// Package shares stores password protected file share records.
//
// Passwords are never stored in plain text. They are hashed with PBKDF2-HMAC
// using a per-share random salt. Verification is constant time and, for
// share IDs that do not exist, an equivalent dummy key derivation runs so
// that response timing cannot reveal whether a share ID is valid.
package shares

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"

	"fileshare/internal/store"
)

const (
	keyLen    = 32
	idBytes   = 16
	saltBytes = 16
)

// ErrDuplicate is returned when a generated share ID collides with an
// existing record. Retrying Create resolves it.
var ErrDuplicate = errors.New("shares: duplicate share ID")

// Record is the persisted share.
type Record struct {
	ID           string `json:"id"`
	Filename     string `json:"filename"`
	Content      []byte `json:"content"`
	Salt         []byte `json:"salt"`
	Iterations   int    `json:"iterations"`
	PasswordHash []byte `json:"password_hash"`
	CreatedAt    string `json:"created_at"`
}

// State is the persisted collection of shares.
type State struct {
	Records map[string]Record `json:"records"`
}

// Manager owns the share store and hashing parameters.
type Manager struct {
	store      *store.JSONFile[State]
	iterations int
	// dummyHash is precomputed once with the same parameters as real
	// records so that verifying a missing share performs comparable work.
	dummySalt []byte
	dummyHash []byte
}

// NewManager opens (or creates) the share store at path and prepares the
// dummy hash used for unknown share IDs.
func NewManager(path string, iterations int) (*Manager, error) {
	file, err := store.Open[State](path)
	if err != nil {
		return nil, err
	}
	dummySalt := make([]byte, saltBytes)
	if _, err := rand.Read(dummySalt); err != nil {
		return nil, fmt.Errorf("shares: generate dummy salt: %w", err)
	}
	dummyHash, err := pbkdf2.Key(sha256.New, "", dummySalt, iterations, keyLen)
	if err != nil {
		return nil, fmt.Errorf("shares: derive dummy hash: %w", err)
	}
	return &Manager{
		store:      file,
		iterations: iterations,
		dummySalt:  dummySalt,
		dummyHash:  dummyHash,
	}, nil
}

// Create stores a new share protected by password.
func (m *Manager) Create(filename, password string, content []byte, createdAt string) (Record, error) {
	id, err := newID()
	if err != nil {
		return Record{}, err
	}
	salt := make([]byte, saltBytes)
	if _, err := rand.Read(salt); err != nil {
		return Record{}, fmt.Errorf("shares: generate salt: %w", err)
	}
	hash, err := pbkdf2.Key(sha256.New, password, salt, m.iterations, keyLen)
	if err != nil {
		return Record{}, fmt.Errorf("shares: hash password: %w", err)
	}

	record := Record{
		ID:           id,
		Filename:     filename,
		Content:      append([]byte(nil), content...),
		Salt:         salt,
		Iterations:   m.iterations,
		PasswordHash: hash,
		CreatedAt:    createdAt,
	}

	err = m.store.Update(State{Records: map[string]Record{}}, func(state *State) error {
		if state.Records == nil {
			state.Records = map[string]Record{}
		}
		if _, exists := state.Records[id]; exists {
			return ErrDuplicate
		}
		state.Records[id] = record
		return nil
	})
	if err != nil {
		return Record{}, err
	}
	return record, nil
}

// Verify reports whether password unlocks the share identified by id.
//
// When the share does not exist, an equivalent PBKDF2 derivation followed by
// a constant-time comparison against the dummy hash still runs, so callers
// cannot distinguish "unknown share" from "wrong password" by timing. The
// boolean reports record existence only for internal bookkeeping; HTTP
// handlers must answer both cases with the same response.
func (m *Manager) Verify(id, password string) (exists bool, ok bool, err error) {
	var record Record
	err = m.store.View(func(state *State) error {
		record, exists = state.Records[id]
		return nil
	})
	if err != nil {
		return false, false, err
	}

	if !exists {
		derived, err := pbkdf2.Key(sha256.New, password, m.dummySalt, m.iterations, keyLen)
		if err != nil {
			return false, false, fmt.Errorf("shares: dummy derivation: %w", err)
		}
		subtle.ConstantTimeCompare(derived, m.dummyHash)
		return false, false, nil
	}

	derived, err := pbkdf2.Key(sha256.New, password, record.Salt, record.Iterations, keyLen)
	if err != nil {
		return true, false, fmt.Errorf("shares: derive password: %w", err)
	}
	return true, subtle.ConstantTimeCompare(derived, record.PasswordHash) == 1, nil
}

// View gives read access to a stored record.
func (m *Manager) View(id string, fn func(Record) error) error {
	return m.store.View(func(state *State) error {
		record, exists := state.Records[id]
		if !exists {
			return ErrNotFound
		}
		return fn(record)
	})
}

// ErrNotFound is returned by View for unknown IDs.
var ErrNotFound = errors.New("shares: record not found")

func newID() (string, error) {
	buf := make([]byte, idBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("shares: generate ID: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
