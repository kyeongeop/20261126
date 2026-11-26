package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// ErrVersionExists is returned when a name@version is republished.
var ErrVersionExists = errors.New("package name@version already published (immutable)")

// ErrReleaseNotFound is returned for an unknown name/version.
var ErrReleaseNotFound = errors.New("release not found")

// Release is a stored, digest-pinned package version.
type Release struct {
	Name        string    `json:"name"`
	Version     string    `json:"version"`
	SHA256      string    `json:"sha256"`
	Size        int64     `json:"size"`
	Files       []string  `json:"files,omitempty"`
	TarballURL  string    `json:"tarball_url,omitempty"`
	PublishedAt time.Time `json:"published_at"`
}

type storedRelease struct {
	Release
	TarPath string `json:"tar_path"`
}

// Store is an on-disk internal package store. Every published artifact is
// verified as a safe tar and pinned by sha256.
type Store struct {
	root string
	mu   sync.RWMutex
	rels map[string]map[string]*storedRelease // name -> version -> release
}

// NewStore opens (and if needed creates) a store under root and loads metadata.
func NewStore(root string) (*Store, error) {
	if err := os.MkdirAll(filepath.Join(root, "packages"), 0o755); err != nil {
		return nil, err
	}
	s := &Store{root: root, rels: map[string]map[string]*storedRelease{}}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) load() error {
	pkgRoot := filepath.Join(s.root, "packages")
	return filepath.WalkDir(pkgRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || d.Name() != "meta.json" {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var rel storedRelease
		if err := json.Unmarshal(b, &rel); err != nil {
			return fmt.Errorf("parse %s: %w", path, err)
		}
		if rel.Name == "" || rel.Version == "" {
			return nil
		}
		s.putMemory(&rel)
		return nil
	})
}

func (s *Store) putMemory(rel *storedRelease) {
	versions, ok := s.rels[rel.Name]
	if !ok {
		versions = map[string]*storedRelease{}
		s.rels[rel.Name] = versions
	}
	versions[rel.Version] = rel
}

// Publish validates and stores a tar artifact. Re-publishing an existing
// name@version is rejected with ErrVersionExists.
func (s *Store) Publish(name, version string, artifact []byte) (*Release, error) {
	if name == "" || version == "" {
		return nil, errors.New("name and version are required")
	}

	info, err := VerifyTar(bytes.NewReader(artifact))
	if err != nil {
		return nil, fmt.Errorf("invalid tar archive: %w", err)
	}
	digest := DigestBytes(artifact)

	s.mu.Lock()
	defer s.mu.Unlock()
	if versions, ok := s.rels[name]; ok {
		if _, exists := versions[version]; exists {
			return nil, ErrVersionExists
		}
	}

	dir := filepath.Join(s.root, "packages", escapeSegment(name), escapeSegment(version))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	tarPath := filepath.Join(dir, "package.tar")
	if err := os.WriteFile(tarPath, artifact, 0o644); err != nil {
		return nil, err
	}

	rel := &storedRelease{
		Release: Release{
			Name:        name,
			Version:     version,
			SHA256:      digest,
			Size:        int64(len(artifact)),
			Files:       info.Entries,
			PublishedAt: time.Now().UTC(),
		},
		TarPath: tarPath,
	}
	meta, err := json.MarshalIndent(rel, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(dir, "meta.json"), meta, 0o644); err != nil {
		return nil, err
	}
	s.putMemory(rel)

	out := rel.Release
	return &out, nil
}

// Get returns a release and its raw tar bytes. Empty version means latest by
// semantic-ish ordering of stored version strings.
func (s *Store) Get(name, version string) (*Release, []byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	versions, ok := s.rels[name]
	if !ok {
		return nil, nil, ErrReleaseNotFound
	}
	if version == "" {
		version = latestVersion(versions)
	}
	rel, ok := versions[version]
	if !ok {
		return nil, nil, ErrReleaseNotFound
	}
	b, err := os.ReadFile(rel.TarPath)
	if err != nil {
		return nil, nil, err
	}
	out := rel.Release
	return &out, b, nil
}

// ReleaseMetadata returns metadata without tar bytes.
func (s *Store) ReleaseMetadata(name, version string) (*Release, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	versions, ok := s.rels[name]
	if !ok {
		return nil, ErrReleaseNotFound
	}
	if version == "" {
		version = latestVersion(versions)
	}
	rel, ok := versions[version]
	if !ok {
		return nil, ErrReleaseNotFound
	}
	out := rel.Release
	return &out, nil
}

// Names lists stored package names.
func (s *Store) Names() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	names := make([]string, 0, len(s.rels))
	for n := range s.rels {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

func latestVersion(m map[string]*storedRelease) string {
	vs := make([]string, 0, len(m))
	for v := range m {
		vs = append(vs, v)
	}
	sort.Strings(vs)
	if len(vs) == 0 {
		return ""
	}
	return vs[len(vs)-1]
}

func escapeSegment(v string) string {
	return url.PathEscape(v)
}
