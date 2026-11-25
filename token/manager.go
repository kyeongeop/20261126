package token

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

const (
	tokenVersion = "pt1"
	signingLabel = "preview-token-v1:"

	defaultTTL = 10 * time.Minute
	maxTTL     = 24 * time.Hour
	// DefaultSessionTTL bounds the exchanged batch grant for a page.
	DefaultSessionTTL = 2 * time.Minute
)

// Manager issues and consumes preview tokens. All state transitions are
// serialized by an internal mutex and persisted through the configured
// Store, so concurrent requests cannot double-spend a token.
type Manager struct {
	secret     []byte
	store      Store
	now        func() time.Time
	defaultTTL time.Duration
	sessionTTL time.Duration

	mu      sync.Mutex
	records map[string]Record
}

// Option customizes a Manager.
type Option func(*Manager)

// WithClock overrides the time source (used in tests).
func WithClock(now func() time.Time) Option {
	return func(m *Manager) {
		if now != nil {
			m.now = now
		}
	}
}

// WithDefaultTTL sets the lifetime used when IssueRequest.TTL is zero.
func WithDefaultTTL(d time.Duration) Option {
	return func(m *Manager) {
		if d > 0 {
			m.defaultTTL = d
		}
	}
}

// WithSessionTTL sets the lifetime of batch grants exchanged from page tokens.
func WithSessionTTL(d time.Duration) Option {
	return func(m *Manager) {
		if d > 0 {
			m.sessionTTL = d
		}
	}
}

// NewManager loads the ledger from store and returns a Manager.
// A nil store keeps the ledger in memory only.
func NewManager(secret []byte, store Store, opts ...Option) (*Manager, error) {
	if len(secret) < 16 {
		return nil, errors.New("token: HMAC secret must be at least 16 bytes")
	}
	m := &Manager{
		secret:     append([]byte(nil), secret...),
		store:      store,
		now:        time.Now,
		defaultTTL: defaultTTL,
		sessionTTL: DefaultSessionTTL,
		records:    map[string]Record{},
	}
	for _, opt := range opts {
		opt(m)
	}
	if store != nil {
		records, err := store.Load()
		if err != nil {
			return nil, err
		}
		m.records = records
	}
	return m, nil
}

// NewEphemeralSecret returns a random 32-byte HMAC secret.
func NewEphemeralSecret() ([]byte, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return nil, fmt.Errorf("token: generate secret: %w", err)
	}
	return buf, nil
}

func randomID(prefix string) (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("token: generate id: %w", err)
	}
	return prefix + hex.EncodeToString(buf), nil
}

func (m *Manager) expiryFor(ttl time.Duration, explicit time.Time) time.Time {
	now := m.now()
	if !explicit.IsZero() {
		return explicit.UTC()
	}
	if ttl <= 0 {
		ttl = m.defaultTTL
	}
	if ttl > maxTTL {
		ttl = maxTTL
	}
	return now.Add(ttl).UTC()
}

// Issue creates and persists a new strict one-time preview token.
func (m *Manager) Issue(req IssueRequest) (string, Claims, error) {
	if strings.TrimSpace(req.File) == "" ||
		strings.TrimSpace(req.Version) == "" ||
		strings.TrimSpace(req.User) == "" ||
		strings.TrimSpace(req.Purpose) == "" {
		return "", Claims{}, fmt.Errorf("%w: file, version, user and purpose are required", ErrInvalidRequest)
	}

	jti, err := randomID("jti_")
	if err != nil {
		return "", Claims{}, err
	}
	now := m.now().UTC()
	c := Claims{
		JTI:       jti,
		Kind:      KindOnce,
		File:      req.File,
		Version:   req.Version,
		User:      req.User,
		Purpose:   req.Purpose,
		Item:      req.Item,
		Items:     append([]string(nil), req.Items...),
		BatchID:   req.BatchID,
		IssuedAt:  now,
		ExpiresAt: m.expiryFor(req.TTL, req.ExpiresAt),
	}
	if !c.ExpiresAt.After(now) {
		return "", Claims{}, fmt.Errorf("%w: expiry must be in the future", ErrInvalidRequest)
	}

	raw, err := m.sign(c)
	if err != nil {
		return "", Claims{}, err
	}

	m.mu.Lock()
	m.records[jti] = Record{Claims: c}
	err = m.persistLocked()
	m.mu.Unlock()
	if err != nil {
		return "", Claims{}, err
	}
	return raw, c, nil
}

// IssueBatch mints one distinct one-time token per thumbnail item. All tokens
// share a BatchID but have unique JTI values, so concurrent page requests are
// consumed independently and never look like replays of one another.
func (m *Manager) IssueBatch(req BatchRequest) (*Batch, error) {
	if strings.TrimSpace(req.File) == "" ||
		strings.TrimSpace(req.Version) == "" ||
		strings.TrimSpace(req.User) == "" {
		return nil, fmt.Errorf("%w: file, version and user are required", ErrInvalidRequest)
	}
	items := req.Items
	if len(items) == 0 {
		items = []string{"thumb-1", "thumb-2", "thumb-3", "thumb-4"}
	}
	purpose := req.Purpose
	if purpose == "" {
		purpose = PurposeThumbnail
	}
	batchID, err := randomID("batch_")
	if err != nil {
		return nil, err
	}

	batch := &Batch{BatchID: batchID, Items: append([]string(nil), items...)}
	for _, item := range items {
		raw, claims, err := m.Issue(IssueRequest{
			File:    req.File,
			Version: req.Version,
			User:    req.User,
			Purpose: purpose,
			TTL:     req.TTL,
			Item:    item,
			BatchID: batchID,
		})
		if err != nil {
			return nil, err
		}
		batch.Tokens = append(batch.Tokens, raw)
		batch.Claims = append(batch.Claims, claims)
		batch.ExpiresAt = claims.ExpiresAt
	}
	return batch, nil
}

// OpenSession consumes a one-time PurposePage token exactly once and returns a
// short-lived KindBatch grant covering the page's thumbnail items. The page
// token can never be exchanged twice.
func (m *Manager) OpenSession(rawPageToken string) (string, Claims, error) {
	pageClaims, err := m.Consume(rawPageToken, Binding{Purpose: PurposePage})
	if err != nil {
		return "", Claims{}, err
	}
	if len(pageClaims.Items) == 0 {
		return "", Claims{}, fmt.Errorf("%w: page token carries no thumbnail items", ErrInvalidRequest)
	}

	now := m.now().UTC()
	exp := now.Add(m.sessionTTL)
	if pageClaims.ExpiresAt.Before(exp) {
		exp = pageClaims.ExpiresAt
	}
	jti, err := randomID("sess_")
	if err != nil {
		return "", Claims{}, err
	}
	grant := Claims{
		JTI:       jti,
		Kind:      KindBatch,
		File:      pageClaims.File,
		Version:   pageClaims.Version,
		User:      pageClaims.User,
		Purpose:   PurposeThumbnail,
		Items:     append([]string(nil), pageClaims.Items...),
		BatchID:   pageClaims.JTI,
		MaxUses:   len(pageClaims.Items),
		IssuedAt:  now,
		ExpiresAt: exp,
	}
	raw, err := m.sign(grant)
	if err != nil {
		return "", Claims{}, err
	}

	m.mu.Lock()
	m.records[jti] = Record{Claims: grant, UsedItems: map[string]time.Time{}}
	err = m.persistLocked()
	m.mu.Unlock()
	if err != nil {
		return "", Claims{}, err
	}
	return raw, grant, nil
}

// Parse verifies the token signature and decodes its claims without touching
// the consumption ledger or checking expiry.
func (m *Manager) Parse(raw string) (Claims, error) {
	var c Claims
	parts := strings.Split(normalizeToken(raw), ".")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return c, fmt.Errorf("%w: malformed token", ErrInvalidToken)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return c, fmt.Errorf("%w: bad payload encoding", ErrInvalidToken)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return c, fmt.Errorf("%w: bad signature encoding", ErrInvalidToken)
	}

	mac := hmac.New(sha256.New, m.secret)
	mac.Write([]byte(signingLabel))
	mac.Write([]byte(parts[0]))
	if !hmac.Equal(sig, mac.Sum(nil)) {
		return c, fmt.Errorf("%w: signature mismatch", ErrInvalidToken)
	}
	if err := json.Unmarshal(payload, &c); err != nil {
		return c, fmt.Errorf("%w: bad claims", ErrInvalidToken)
	}
	if c.JTI == "" || c.File == "" || c.Version == "" || c.User == "" || c.Purpose == "" {
		return c, fmt.Errorf("%w: incomplete claims", ErrInvalidToken)
	}
	if c.Kind == "" {
		c.Kind = KindOnce
	}
	return c, nil
}

// Consume verifies raw, checks expiry and the request binding, then
// atomically records consumption. A KindOnce token succeeds exactly once;
// a KindBatch grant succeeds once per allow-listed item.
func (m *Manager) Consume(raw string, want Binding) (Claims, error) {
	c, err := m.Parse(raw)
	if err != nil {
		return Claims{}, err
	}
	now := m.now()
	if !c.ExpiresAt.After(now) {
		return Claims{}, fmt.Errorf("%w at %s", ErrExpired, c.ExpiresAt.Format(time.RFC3339))
	}
	if err := want.Match(c); err != nil {
		return Claims{}, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	rec, ok := m.records[c.JTI]
	if !ok {
		return Claims{}, ErrUnknownToken
	}

	switch c.Kind {
	case KindBatch:
		item := want.Item
		if item == "" {
			return Claims{}, ErrItemRequired
		}
		if !containsString(c.Items, item) {
			return Claims{}, fmt.Errorf("%w: %q", ErrItemNotAllowed, item)
		}
		if rec.UsedItems == nil {
			rec.UsedItems = map[string]time.Time{}
		}
		if usedAt, dup := rec.UsedItems[item]; dup {
			return Claims{}, fmt.Errorf("%w: item %q at %s", ErrReplay, item, usedAt.Format(time.RFC3339))
		}
		if c.MaxUses > 0 && rec.Uses >= c.MaxUses {
			return Claims{}, fmt.Errorf("%w: batch use limit %d reached", ErrReplay, c.MaxUses)
		}
		rec.UsedItems[item] = now.UTC()
		rec.Uses++
	default: // KindOnce
		if rec.Used {
			usedAt := "unknown"
			if rec.UsedAt != nil {
				usedAt = rec.UsedAt.Format(time.RFC3339)
			}
			return Claims{}, fmt.Errorf("%w at %s", ErrReplay, usedAt)
		}
		rec.Used = true
		used := now.UTC()
		rec.UsedAt = &used
	}

	m.records[c.JTI] = rec
	if err := m.persistLocked(); err != nil {
		return Claims{}, err
	}
	return c, nil
}

// Record returns a copy of the ledger entry for jti (used by tests/admin).
func (m *Manager) Record(jti string) (Record, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.records[jti]
	return rec, ok
}

// Check validates a token exactly like Consume (signature, expiry, binding
// and consumption state) but never mutates the ledger. It lets callers
// inspect whether a token is still usable without spending it.
func (m *Manager) Check(raw string, want Binding) (Claims, error) {
	c, err := m.Parse(raw)
	if err != nil {
		return Claims{}, err
	}
	if !c.ExpiresAt.After(m.now()) {
		return Claims{}, fmt.Errorf("%w at %s", ErrExpired, c.ExpiresAt.Format(time.RFC3339))
	}
	if err := want.Match(c); err != nil {
		return Claims{}, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.records[c.JTI]
	if !ok {
		return Claims{}, ErrUnknownToken
	}
	switch c.Kind {
	case KindBatch:
		if want.Item != "" {
			if !containsString(c.Items, want.Item) {
				return Claims{}, fmt.Errorf("%w: %q", ErrItemNotAllowed, want.Item)
			}
			if _, used := rec.UsedItems[want.Item]; used {
				return Claims{}, fmt.Errorf("%w: item %q already consumed", ErrReplay, want.Item)
			}
		}
	default:
		if rec.Used {
			return Claims{}, ErrReplay
		}
	}
	return c, nil
}

func (m *Manager) persistLocked() error {
	if m.store == nil {
		return nil
	}
	return m.store.Save(m.records)
}

func (m *Manager) sign(c Claims) (string, error) {
	payload, err := json.Marshal(c)
	if err != nil {
		return "", fmt.Errorf("token: encode claims: %w", err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, m.secret)
	mac.Write([]byte(signingLabel))
	mac.Write([]byte(encoded))
	sig := mac.Sum(nil)
	return tokenVersion + "." + encoded + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// normalizeToken accepts both "payload.signature" and the versioned
// "pt1.payload.signature" serialization produced by sign.
func normalizeToken(raw string) string {
	parts := strings.Split(strings.TrimSpace(raw), ".")
	if len(parts) == 3 && parts[0] == tokenVersion {
		return parts[1] + "." + parts[2]
	}
	return strings.TrimSpace(raw)
}

func containsString(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}
