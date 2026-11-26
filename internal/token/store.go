package token

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// Record is the stored metadata for a token. The secret itself is
// never persisted, only its sha256 hash.
type Record struct {
	ID         string    `json:"id"`
	Label      string    `json:"label"`
	Scope      Scope     `json:"scope"`
	SecretHash string    `json:"secret_hash"`
	CreatedAt  time.Time `json:"created_at"`
	Revoked    bool      `json:"revoked"`
}

// Store is a file-backed token store rooted inside the repository data dir.
type Store struct {
	mu      sync.Mutex
	path    string
	records map[string]Record // by ID
}

// OpenStore loads (or initializes) the token store at dir/tokens.json.
func OpenStore(dir string) (*Store, error) {
	s := &Store{
		path:    filepath.Join(dir, "tokens.json"),
		records: make(map[string]Record),
	}
	data, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	var list []Record
	if err := json.Unmarshal(data, &list); err != nil {
		return nil, err
	}
	for _, r := range list {
		s.records[r.ID] = r
	}
	return s, nil
}

// Create mints a new token for the given scope and returns the secret
// exactly once; only its hash is stored.
func (s *Store) Create(label string, scope Scope) (secret string, rec Record, err error) {
	if err := scope.Validate(); err != nil {
		return "", Record{}, err
	}
	secret, err = NewSecret()
	if err != nil {
		return "", Record{}, err
	}
	var idBuf [8]byte
	if _, err := rand.Read(idBuf[:]); err != nil {
		return "", Record{}, err
	}
	rec = Record{
		ID:         "tok_" + hex.EncodeToString(idBuf[:]),
		Label:      label,
		Scope:      scope,
		SecretHash: HashSecret(secret),
		CreatedAt:  time.Now().UTC(),
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records[rec.ID] = rec
	if err := s.saveLocked(); err != nil {
		delete(s.records, rec.ID)
		return "", Record{}, err
	}
	return secret, rec, nil
}

// Lookup resolves a secret to its record. The boolean is false for
// unknown or revoked tokens; callers must not distinguish the two.
func (s *Store) Lookup(secret string) (Record, bool) {
	h := HashSecret(secret)
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.records {
		if r.SecretHash == h && !r.Revoked {
			return r, true
		}
	}
	return Record{}, false
}

// List returns all records (metadata only), sorted by creation time.
func (s *Store) List() []Record {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Record, 0, len(s.records))
	for _, r := range s.records {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out
}

// Revoke disables a token by ID.
func (s *Store) Revoke(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.records[id]
	if !ok || r.Revoked {
		return false
	}
	r.Revoked = true
	s.records[id] = r
	return s.saveLocked() == nil
}

func (s *Store) saveLocked() error {
	list := make([]Record, 0, len(s.records))
	for _, r := range s.records {
		list = append(list, r)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].ID < list[j].ID })
	data, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}
