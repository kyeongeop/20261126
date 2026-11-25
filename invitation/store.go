// Package invitation implements the one-time enrollment invitation aggregate
// and its concurrency-safe in-memory store.
//
// An invitation is bound to a target service name, a validity window (the
// invitation's own expiry plus the lifetime of the certificate it may issue)
// and a single purpose. The plaintext token is shown exactly once by Create;
// only its SHA-256 hash is retained.
package invitation

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"certgateway/identity"
)

// State is the invitation lifecycle state.
type State string

const (
	StatePending  State = "pending"
	StateConsumed State = "consumed"
	StateRevoked  State = "revoked"
	StateExpired  State = "expired"
)

// Sentinel errors returned by the store and enrollment flow.
var (
	ErrNotFound       = errors.New("invitation: not found")
	ErrInvalidToken   = errors.New("invitation: invalid token")
	ErrUsed           = errors.New("invitation: already used")
	ErrExpired        = errors.New("invitation: expired")
	ErrRevoked        = errors.New("invitation: revoked")
	ErrInvalidService = errors.New("invitation: service name is required")
	ErrInvalidPurpose = errors.New("invitation: invalid purpose")
	ErrInvalidTTL     = errors.New("invitation: durations must be positive")
)

// Default TTLs used when the caller passes zero durations.
const (
	DefaultInviteTTL = 15 * time.Minute
	DefaultCertTTL   = 24 * time.Hour
)

// Invitation is the stored aggregate; returned values are copies.
type Invitation struct {
	ID           string
	TokenHash    [sha256.Size]byte
	Service      string
	Purpose      string
	CreatedAt    time.Time
	ExpiresAt    time.Time
	CertValidity time.Duration
	State        State
	UsedAt       time.Time
	CertSerial   string
}

// Store is a mutex-guarded in-memory invitation repository. It never touches
// an external database.
type Store struct {
	mu        sync.Mutex
	byID      map[string]*Invitation
	tokenToID map[[sha256.Size]byte]string
	NowFunc   func() time.Time
}

// NewStore creates an empty Store.
func NewStore() *Store {
	return &Store{
		byID:      make(map[string]*Invitation),
		tokenToID: make(map[[sha256.Size]byte]string),
	}
}

// Now returns the configured clock or wall-clock time.
func (s *Store) Now() time.Time {
	if s.NowFunc != nil {
		return s.NowFunc()
	}
	return time.Now()
}

// CreateInput parameterizes a new invitation.
type CreateInput struct {
	Service      string
	Purpose      string
	InviteTTL    time.Duration
	CertValidity time.Duration
}

// Create persists a pending invitation and returns the one-time plaintext
// token that clients present during enrollment. The token cannot be recovered
// later from the store.
func (s *Store) Create(in CreateInput) (*Invitation, string, error) {
	if in.Service == "" {
		return nil, "", ErrInvalidService
	}
	if !identity.ValidPurpose(in.Purpose) {
		return nil, "", fmt.Errorf("%w: %q", ErrInvalidPurpose, in.Purpose)
	}
	if in.InviteTTL == 0 {
		in.InviteTTL = DefaultInviteTTL
	}
	if in.CertValidity == 0 {
		in.CertValidity = DefaultCertTTL
	}
	if in.InviteTTL < 0 || in.CertValidity < 0 {
		return nil, "", ErrInvalidTTL
	}

	id, err := randomID("inv_")
	if err != nil {
		return nil, "", err
	}
	token, err := randomToken()
	if err != nil {
		return nil, "", err
	}

	now := s.Now()
	inv := &Invitation{
		ID:           id,
		TokenHash:    HashToken(token),
		Service:      in.Service,
		Purpose:      in.Purpose,
		CreatedAt:    now,
		ExpiresAt:    now.Add(in.InviteTTL),
		CertValidity: in.CertValidity,
		State:        StatePending,
	}

	s.mu.Lock()
	s.byID[id] = inv
	s.tokenToID[inv.TokenHash] = id
	s.mu.Unlock()

	copyInv := *inv
	return &copyInv, token, nil
}

// HashToken hashes a plaintext invitation token.
func HashToken(token string) [sha256.Size]byte {
	return sha256.Sum256([]byte(token))
}

// AuthenticateToken validates a bearer invitation token and returns a copy of
// the pending, unexpired invitation it belongs to.
func (s *Store) AuthenticateToken(token string) (*Invitation, error) {
	if token == "" {
		return nil, ErrInvalidToken
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	id, ok := s.tokenToID[HashToken(token)]
	if !ok {
		return nil, ErrNotFound
	}
	inv := s.byID[id]
	if inv == nil {
		return nil, ErrNotFound
	}
	if err := s.checkLiveLocked(inv); err != nil {
		return nil, err
	}
	cp := *inv
	return &cp, nil
}

// Get returns a copy of the invitation by ID.
func (s *Store) Get(id string) (*Invitation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	inv, ok := s.byID[id]
	if !ok {
		return nil, ErrNotFound
	}
	cp := *inv
	return &cp, nil
}

// Consume atomically transitions a live pending invitation to consumed and
// records the serial number of the certificate issued against it. It is the
// single serialization point that guarantees at most one issuance.
func (s *Store) Consume(id, certSerial string) (*Invitation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	inv, ok := s.byID[id]
	if !ok {
		return nil, ErrNotFound
	}
	switch inv.State {
	case StateConsumed:
		return nil, fmt.Errorf("%w: certificate serial %s", ErrUsed, inv.CertSerial)
	case StateRevoked:
		return nil, ErrRevoked
	case StateExpired:
		return nil, ErrExpired
	}
	if err := s.checkLiveLocked(inv); err != nil {
		return nil, err
	}

	inv.State = StateConsumed
	inv.UsedAt = s.Now()
	inv.CertSerial = certSerial
	cp := *inv
	return &cp, nil
}

// Revoke marks a pending invitation as revoked.
func (s *Store) Revoke(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	inv, ok := s.byID[id]
	if !ok {
		return ErrNotFound
	}
	if inv.State == StatePending {
		inv.State = StateRevoked
	}
	return nil
}

// checkLiveLocked enforces pending state and expiry; it lazily records expiry.
// Callers must hold s.mu.
func (s *Store) checkLiveLocked(inv *Invitation) error {
	switch inv.State {
	case StateConsumed:
		return fmt.Errorf("%w: certificate serial %s", ErrUsed, inv.CertSerial)
	case StateRevoked:
		return ErrRevoked
	case StateExpired:
		return ErrExpired
	}
	if !s.Now().Before(inv.ExpiresAt) {
		inv.State = StateExpired
		return ErrExpired
	}
	return nil
}

func randomID(prefix string) (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("invitation: random id: %w", err)
	}
	return prefix + hex.EncodeToString(b), nil
}

func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("invitation: random token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
