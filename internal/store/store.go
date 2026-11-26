// Package store persists packages as tar archives inside the
// repository data directory, with sha256 digests and revocation
// metadata kept alongside each archive.
package store

import (
	"archive/tar"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// ErrNotFound is returned for missing or revoked packages.
var ErrNotFound = errors.New("package not found")

// ErrExists is returned when publishing a version that already exists.
var ErrExists = errors.New("package version already exists")

// Meta describes one stored package version.
type Meta struct {
	Namespace  string    `json:"namespace"`
	Name       string    `json:"name"`
	Version    string    `json:"version"`
	SHA256     string    `json:"sha256"`
	Size       int64     `json:"size"`
	UploadedBy string    `json:"uploaded_by"`
	CreatedAt  time.Time `json:"created_at"`
	Revoked    bool      `json:"revoked"`
	RevokedBy  string    `json:"revoked_by,omitempty"`
	RevokedAt  time.Time `json:"revoked_at,omitempty"`
	Reason     string    `json:"revoke_reason,omitempty"`
}

// Store is a file-backed package store.
type Store struct {
	mu   sync.Mutex
	root string
}

// Open creates the store rooted at dir/packages.
func Open(dir string) (*Store, error) {
	root := filepath.Join(dir, "packages")
	if err := os.MkdirAll(root, 0o755); err != nil {
		return nil, err
	}
	return &Store{root: root}, nil
}

// ValidPart rejects path segments that could escape the store root.
func ValidPart(s string) bool {
	if s == "" || s == "." || s == ".." {
		return false
	}
	return !strings.ContainsAny(s, "/\\\x00")
}

func (s *Store) paths(ns, name, version string) (tarPath, metaPath string) {
	base := filepath.Join(append([]string{s.root}, splitNS(ns)...)...)
	base = filepath.Join(base, name)
	return filepath.Join(base, version+".tar"), filepath.Join(base, version+".json")
}

func splitNS(ns string) []string {
	parts := strings.Split(ns, "/")
	out := parts[:0]
	for _, p := range parts {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// Publish validates and stores a tar archive. Existing versions are
// never overwritten.
func (s *Store) Publish(ns, name, version, actor string, r io.Reader) (*Meta, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	tarPath, metaPath := s.paths(ns, name, version)
	if _, err := os.Stat(metaPath); err == nil {
		return nil, ErrExists
	}
	if err := os.MkdirAll(filepath.Dir(tarPath), 0o755); err != nil {
		return nil, err
	}

	tmp, err := os.CreateTemp(filepath.Dir(tarPath), ".upload-*")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmp.Name())

	h := sha256.New()
	size, err := io.Copy(io.MultiWriter(tmp, h), r)
	if err != nil {
		tmp.Close()
		return nil, err
	}
	if err := tmp.Close(); err != nil {
		return nil, err
	}
	if err := validateTar(tmp.Name()); err != nil {
		return nil, fmt.Errorf("invalid tar archive: %w", err)
	}
	if err := os.Rename(tmp.Name(), tarPath); err != nil {
		return nil, err
	}

	m := &Meta{
		Namespace:  ns,
		Name:       name,
		Version:    version,
		SHA256:     hex.EncodeToString(h.Sum(nil)),
		Size:       size,
		UploadedBy: actor,
		CreatedAt:  time.Now().UTC(),
	}
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(metaPath, data, 0o644); err != nil {
		return nil, err
	}
	return m, nil
}

// validateTar ensures the file is a readable tar archive and that no
// entry escapes its root.
func validateTar(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	tr := tar.NewReader(f)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		clean := filepath.Clean(hdr.Name)
		if strings.HasPrefix(clean, "..") || filepath.IsAbs(clean) {
			return fmt.Errorf("unsafe entry %q", hdr.Name)
		}
	}
}

// Fetch returns the metadata and archive for a live package version.
// Revoked versions are indistinguishable from missing ones.
func (s *Store) Fetch(ns, name, version string) (*Meta, *os.File, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tarPath, metaPath := s.paths(ns, name, version)
	m, err := s.readMeta(metaPath)
	if err != nil || m.Revoked {
		return nil, nil, ErrNotFound
	}
	f, err := os.Open(tarPath)
	if err != nil {
		return nil, nil, ErrNotFound
	}
	return m, f, nil
}

// Meta returns metadata for a live package version without the archive.
func (s *Store) Meta(ns, name, version string) (*Meta, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, metaPath := s.paths(ns, name, version)
	m, err := s.readMeta(metaPath)
	if err != nil || m.Revoked {
		return nil, ErrNotFound
	}
	return m, nil
}

// Revoke marks a version withdrawn. The archive stays on disk but is
// no longer fetchable.
func (s *Store) Revoke(ns, name, version, actor, reason string) (*Meta, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, metaPath := s.paths(ns, name, version)
	m, err := s.readMeta(metaPath)
	if err != nil || m.Revoked {
		return nil, ErrNotFound
	}
	m.Revoked = true
	m.RevokedBy = actor
	m.RevokedAt = time.Now().UTC()
	m.Reason = reason
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(metaPath, data, 0o644); err != nil {
		return nil, err
	}
	return m, nil
}

func (s *Store) readMeta(metaPath string) (*Meta, error) {
	data, err := os.ReadFile(metaPath)
	if err != nil {
		return nil, err
	}
	var m Meta
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	return &m, nil
}
