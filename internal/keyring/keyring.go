// Package keyring manages the file encryption key (KEK) versions used to wrap
// per-file-version data keys (DEKs). Rotation adds a brand new KEK version but
// never removes or rewrites older KEKs, so historical ciphertext stays
// decryptable forever without touching old blobs.
package keyring

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"fileshare/internal/envelope"
)

// Meta describes one KEK version. The raw key material lives in a separate
// key file (keys/k<version>.key) and is never embedded in the manifest.
type Meta struct {
	Version   int       `json:"version"`
	SHA256    string    `json:"sha256"`
	CreatedAt time.Time `json:"created_at"`
	CreatedBy string    `json:"created_by"`
}

// manifest is the on-disk keyring.json document.
type manifest struct {
	ActiveVersion int    `json:"active_version"`
	Keys          []Meta `json:"keys"`
}

// Keyring holds all KEK versions loaded from a directory.
type Keyring struct {
	mu     sync.RWMutex
	dir    string
	keys   map[int][]byte
	meta   map[int]Meta
	active int
}

// Open loads the keyring from dir, creating the first KEK version if none
// exists. The creator identifies the principal performing initialization.
func Open(dir, creator string) (*Keyring, error) {
	if err := os.MkdirAll(filepath.Join(dir, "keys"), 0o700); err != nil {
		return nil, err
	}
	kr := &Keyring{
		dir:  dir,
		keys: make(map[int][]byte),
		meta: make(map[int]Meta),
	}

	data, err := os.ReadFile(kr.manifestPath())
	switch {
	case err == nil:
		var m manifest
		if err := json.Unmarshal(data, &m); err != nil {
			return nil, fmt.Errorf("keyring: parse manifest: %w", err)
		}
		for _, entry := range m.Keys {
			raw, err := os.ReadFile(kr.keyPath(entry.Version))
			if err != nil {
				return nil, fmt.Errorf("keyring: load key v%d: %w", entry.Version, err)
			}
			key, err := hex.DecodeString(string(raw))
			if err != nil || len(key) != 32 {
				return nil, fmt.Errorf("keyring: invalid key material for v%d", entry.Version)
			}
			kr.keys[entry.Version] = key
			kr.meta[entry.Version] = entry
		}
		kr.active = m.ActiveVersion
		if _, ok := kr.keys[kr.active]; !ok {
			return nil, errors.New("keyring: active version missing from key files")
		}
	case errors.Is(err, os.ErrNotExist):
		if _, err := kr.rotateLocked(creator); err != nil {
			return nil, err
		}
	default:
		return nil, err
	}
	return kr, nil
}

// Rotate generates a new KEK version, stores it, and marks it active. Old KEK
// versions remain on disk and usable for unwrapping historical DEKs.
func (kr *Keyring) Rotate(creator string) (Meta, error) {
	kr.mu.Lock()
	defer kr.mu.Unlock()
	return kr.rotateLocked(creator)
}

func (kr *Keyring) rotateLocked(creator string) (Meta, error) {
	key, err := envelope.GenerateKey()
	if err != nil {
		return Meta{}, err
	}
	version := kr.active + 1
	entry := Meta{
		Version:   version,
		SHA256:    envelope.SHA256(key),
		CreatedAt: time.Now().UTC(),
		CreatedBy: creator,
	}
	if err := os.WriteFile(kr.keyPath(version),
		[]byte(hex.EncodeToString(key)), 0o600); err != nil {
		return Meta{}, err
	}
	kr.keys[version] = key
	kr.meta[version] = entry
	kr.active = version
	if err := kr.persistLocked(); err != nil {
		return Meta{}, err
	}
	return entry, nil
}

// ActiveKey returns the active KEK material and its metadata.
func (kr *Keyring) ActiveKey() ([]byte, Meta, error) {
	kr.mu.RLock()
	defer kr.mu.RUnlock()
	key, ok := kr.keys[kr.active]
	if !ok {
		return nil, Meta{}, errors.New("keyring: no active key")
	}
	return key, kr.meta[kr.active], nil
}

// Key returns the KEK material for an arbitrary historical version.
func (kr *Keyring) Key(version int) ([]byte, Meta, error) {
	kr.mu.RLock()
	defer kr.mu.RUnlock()
	key, ok := kr.keys[version]
	if !ok {
		return nil, Meta{}, fmt.Errorf("keyring: key version %d not found", version)
	}
	return key, kr.meta[version], nil
}

// ActiveVersion returns the currently active KEK version number.
func (kr *Keyring) ActiveVersion() int {
	kr.mu.RLock()
	defer kr.mu.RUnlock()
	return kr.active
}

// List returns metadata for every KEK version ordered by version number.
func (kr *Keyring) List() []Meta {
	kr.mu.RLock()
	defer kr.mu.RUnlock()
	out := make([]Meta, 0, len(kr.meta))
	for _, entry := range kr.meta {
		out = append(out, entry)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Version < out[j].Version })
	return out
}

func (kr *Keyring) persistLocked() error {
	m := manifest{ActiveVersion: kr.active}
	for _, entry := range kr.meta {
		m.Keys = append(m.Keys, entry)
	}
	sort.Slice(m.Keys, func(i, j int) bool { return m.Keys[i].Version < m.Keys[j].Version })
	return writeJSON(kr.manifestPath(), m)
}

func (kr *Keyring) manifestPath() string {
	return filepath.Join(kr.dir, "keyring.json")
}

func (kr *Keyring) keyPath(version int) string {
	return filepath.Join(kr.dir, "keys", fmt.Sprintf("k%d.key", version))
}

// writeJSON writes value to path atomically (temp file + rename) with 0600
// permissions because the documents reference key material and wrapped DEKs.
func writeJSON(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
