package token

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Record is the persisted ledger entry for one token. It embeds the signed
// claims plus the server-side consumption state.
type Record struct {
	Claims

	// Used is true once a KindOnce token has been consumed.
	Used bool `json:"used,omitempty"`
	// UsedAt records when the one-time token was consumed.
	UsedAt *time.Time `json:"used_at,omitempty"`

	// Uses counts consumptions of a KindBatch grant.
	Uses int `json:"uses,omitempty"`
	// UsedItems records per-item consumption of a KindBatch grant.
	UsedItems map[string]time.Time `json:"used_items,omitempty"`
}

// Store persists the token consumption ledger. Implementations must be safe
// for concurrent use; Manager additionally serializes mutations.
type Store interface {
	Load() (map[string]Record, error)
	Save(records map[string]Record) error
}

// JSONStore is a Store backed by a single JSON file using os and
// encoding/json. Saves are atomic: data is written to a temp file in the
// same directory and renamed over the target.
type JSONStore struct {
	path string
	mu   sync.Mutex
}

// NewJSONStore creates a JSONStore at path. The file need not exist yet.
func NewJSONStore(path string) *JSONStore {
	return &JSONStore{path: path}
}

// Path returns the configured JSON file path.
func (s *JSONStore) Path() string { return s.path }

// Load reads the ledger. A missing file yields an empty ledger.
func (s *JSONStore) Load() (map[string]Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]Record{}, nil
		}
		return nil, fmt.Errorf("token: read store: %w", err)
	}
	if len(data) == 0 {
		return map[string]Record{}, nil
	}
	var records map[string]Record
	if err := json.Unmarshal(data, &records); err != nil {
		return nil, fmt.Errorf("token: parse store %s: %w", s.path, err)
	}
	if records == nil {
		records = map[string]Record{}
	}
	return records, nil
}

// Save atomically replaces the ledger file with records.
func (s *JSONStore) Save(records map[string]Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := json.MarshalIndent(records, "", "  ")
	if err != nil {
		return fmt.Errorf("token: encode store: %w", err)
	}

	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("token: create store dir: %w", err)
	}

	tmp, err := os.CreateTemp(dir, ".tokens-*.json.tmp")
	if err != nil {
		return fmt.Errorf("token: create temp store: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after a successful rename

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("token: write store: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("token: close store: %w", err)
	}
	if err := os.Chmod(tmpName, 0o600); err != nil {
		return fmt.Errorf("token: chmod store: %w", err)
	}
	if err := os.Rename(tmpName, s.path); err != nil {
		return fmt.Errorf("token: commit store: %w", err)
	}
	return nil
}
