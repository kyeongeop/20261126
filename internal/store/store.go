// Package store implements versioned, envelope-encrypted file storage backed
// entirely by the local filesystem. Every upload creates a new immutable
// ciphertext blob with its own DEK and an append-only manifest entry; reads can
// target any historical version and never mutate stored ciphertext.
package store

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"fileshare/internal/envelope"
	"fileshare/internal/keyring"
)

// ErrNotFound is returned when a file or version does not exist.
var ErrNotFound = errors.New("store: not found")

// ErrChecksum is returned when a decrypted blob fails checksum verification.
var ErrChecksum = errors.New("store: checksum mismatch")

// Store manages encrypted files under a data directory.
type Store struct {
	mu  sync.Mutex
	dir string
	kr  *keyring.Keyring
}

// New creates a Store rooted at dataDir. The directory layout is:
//
//	dataDir/
//	  keyring.json, keys/           (managed by the keyring package)
//	  files/<id>/manifest.json
//	  files/<id>/v<number>.enc
func New(dataDir string, kr *keyring.Keyring) *Store {
	return &Store{dir: dataDir, kr: kr}
}

// AddVersion stores plaintext as a new immutable version of the logical file
// id. A fresh DEK is generated per version and wrapped with the currently
// active KEK, so key rotation never requires rewriting old ciphertext.
func (s *Store) AddVersion(id, name, creator, note string, plaintext []byte) (Version, error) {
	if strings.TrimSpace(id) == "" {
		return Version{}, errors.New("store: empty file id")
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	dir := s.fileDir(id)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return Version{}, err
	}

	m, err := s.loadLocked(id)
	if err != nil {
		return Version{}, err
	}
	m.ID = id
	if m.Name == "" {
		if name != "" {
			m.Name = name
		} else {
			m.Name = id
		}
	}

	dek, err := envelope.GenerateKey()
	if err != nil {
		return Version{}, err
	}
	kek, keyMeta, err := s.kr.ActiveKey()
	if err != nil {
		return Version{}, err
	}
	wrappedDEK, err := envelope.Seal(kek, dek)
	if err != nil {
		return Version{}, err
	}

	blob, err := envelope.Seal(dek, plaintext)
	if err != nil {
		return Version{}, err
	}

	number := m.Latest + 1
	blobName := fmt.Sprintf("v%d.enc", number)
	if err := os.WriteFile(filepath.Join(dir, blobName), blob, 0o600); err != nil {
		return Version{}, err
	}

	entry := Version{
		Number:       number,
		BlobPath:     filepath.Join("files", id, blobName),
		KeyVersion:   keyMeta.Version,
		WrappedDEK:   wrappedDEK,
		PlainSHA256:  envelope.SHA256(plaintext),
		CipherSHA256: envelope.SHA256(blob),
		Size:         int64(len(plaintext)),
		CreatedAt:    time.Now().UTC(),
		CreatedBy:    creator,
		Note:         note,
	}
	m.Versions = append(m.Versions, entry)
	m.Latest = number
	m.LastUpdated = entry.CreatedAt
	if err := s.saveLocked(id, m); err != nil {
		return Version{}, err
	}
	return entry, nil
}

// ReadVersion decrypts any historical version. The version's DEK is unwrapped
// with the exact KEK version recorded at upload time; the stored blob and
// manifest are never modified. Both ciphertext and plaintext checksums are
// verified before returning.
func (s *Store) ReadVersion(id string, number int) ([]byte, Version, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	m, err := s.loadLocked(id)
	if err != nil {
		return nil, Version{}, err
	}
	entry, ok := findVersion(m, number)
	if !ok {
		return nil, Version{}, fmt.Errorf("%w: %s v%d", ErrNotFound, id, number)
	}

	blob, err := os.ReadFile(filepath.Join(s.dir, entry.BlobPath))
	if err != nil {
		return nil, Version{}, err
	}
	if subtle.ConstantTimeCompare([]byte(envelope.SHA256(blob)), []byte(entry.CipherSHA256)) != 1 {
		return nil, Version{}, fmt.Errorf("%w: ciphertext of %s v%d", ErrChecksum, id, number)
	}

	kek, _, err := s.kr.Key(entry.KeyVersion)
	if err != nil {
		return nil, Version{}, err
	}
	dek, err := envelope.Open(kek, entry.WrappedDEK)
	if err != nil {
		return nil, Version{}, fmt.Errorf("unwrap DEK: %w", err)
	}
	plaintext, err := envelope.Open(dek, blob)
	if err != nil {
		return nil, Version{}, fmt.Errorf("decrypt blob: %w", err)
	}
	if subtle.ConstantTimeCompare([]byte(envelope.SHA256(plaintext)), []byte(entry.PlainSHA256)) != 1 {
		return nil, Version{}, fmt.Errorf("%w: plaintext of %s v%d", ErrChecksum, id, number)
	}
	return plaintext, entry, nil
}

// PublicManifest returns the metadata-only ledger view for a file.
func (s *Store) PublicManifest(id string) (PublicManifest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, err := s.loadLocked(id)
	if err != nil {
		return PublicManifest{}, err
	}
	return toPublic(m), nil
}

// ListFiles returns the public manifest of every stored file, sorted by ID.
func (s *Store) ListFiles() ([]PublicManifest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	entries, err := os.ReadDir(filepath.Join(s.dir, "files"))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return []PublicManifest{}, nil
		}
		return nil, err
	}
	out := make([]PublicManifest, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		m, err := s.loadLocked(e.Name())
		if err != nil {
			return nil, err
		}
		out = append(out, toPublic(m))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (s *Store) loadLocked(id string) (*Manifest, error) {
	path := filepath.Join(s.fileDir(id), "manifest.json")
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return &Manifest{Versions: []Version{}}, nil
		}
		return nil, err
	}
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("store: parse manifest %s: %w", id, err)
	}
	if m.Versions == nil {
		m.Versions = []Version{}
	}
	return &m, nil
}

func (s *Store) saveLocked(id string, m *Manifest) error {
	return writeJSONAtomic(filepath.Join(s.fileDir(id), "manifest.json"), m)
}

func (s *Store) fileDir(id string) string {
	return filepath.Join(s.dir, "files", id)
}

func findVersion(m *Manifest, number int) (Version, bool) {
	for _, v := range m.Versions {
		if v.Number == number {
			return v, true
		}
	}
	return Version{}, false
}
