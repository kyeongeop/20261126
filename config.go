package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// LoadConfig reads a depguard.json document. Relative data paths are resolved
// against the config file's directory so fixtures work regardless of cwd.
func LoadConfig(filename string) (*Config, error) {
	abs, err := filepath.Abs(filename)
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(abs)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", filename, err)
	}
	var cfg Config
	if err := json.Unmarshal(b, &cfg); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", filename, err)
	}
	cfg.RootDir = filepath.Dir(abs)
	cfg.applyDefaults()
	return &cfg, nil
}

func (c *Config) applyDefaults() {
	if c.Namespace.Fallback == "" {
		c.Namespace.Fallback = "deny"
	}
}

// ResolvePath resolves a config-relative path. Absolute paths are returned
// unchanged. Empty values return empty.
func (c *Config) ResolvePath(p string) string {
	if p == "" {
		return ""
	}
	if filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(c.RootDir, p)
}

// LoadPublicCatalog reads the offline public-registry fixture. An empty path
// yields an empty catalog (no same-name evidence).
func LoadPublicCatalog(filename string) (*PublicCatalog, error) {
	if filename == "" {
		return &PublicCatalog{Packages: map[string]PublicPackage{}}, nil
	}
	b, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("read public catalog: %w", err)
	}
	var cat PublicCatalog
	if err := json.Unmarshal(b, &cat); err != nil {
		return nil, fmt.Errorf("parse public catalog: %w", err)
	}
	if cat.Packages == nil {
		cat.Packages = map[string]PublicPackage{}
	}
	return &cat, nil
}

// Has reports whether the exact (case-insensitive) name is public.
func (c *PublicCatalog) Has(name string) bool {
	if c == nil {
		return false
	}
	if _, ok := c.Packages[name]; ok {
		return true
	}
	_, ok := c.Packages[lowerName(name)]
	return ok
}

// Get returns the catalog entry using exact then lower-cased lookup.
func (c *PublicCatalog) Get(name string) (PublicPackage, bool) {
	if c == nil {
		return PublicPackage{}, false
	}
	if p, ok := c.Packages[name]; ok {
		return p, ok
	}
	p, ok := c.Packages[lowerName(name)]
	return p, ok
}

// LoadInternalIndex reads the trusted internal index fixture.
func LoadInternalIndex(filename string) (*InternalIndex, error) {
	if filename == "" {
		return &InternalIndex{Packages: map[string]InternalPackage{}}, nil
	}
	b, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("read internal index: %w", err)
	}
	var idx InternalIndex
	if err := json.Unmarshal(b, &idx); err != nil {
		return nil, fmt.Errorf("parse internal index: %w", err)
	}
	if idx.Packages == nil {
		idx.Packages = map[string]InternalPackage{}
	}
	return &idx, nil
}

// Release returns the named release, falling back to Latest when version is
// empty. The bool reports existence.
func (idx *InternalIndex) Release(name, version string) (InternalPackage, InternalRelease, bool) {
	if idx == nil {
		return InternalPackage{}, InternalRelease{}, false
	}
	pkg, ok := idx.Packages[name]
	if !ok {
		if p2, ok2 := idx.Packages[lowerName(name)]; ok2 {
			pkg = p2
			ok = true
		}
	}
	if !ok {
		return InternalPackage{}, InternalRelease{}, false
	}
	if version == "" {
		version = pkg.Latest
	}
	if rel, ok := pkg.Versions[version]; ok {
		if rel.Version == "" {
			rel.Version = version
		}
		return pkg, rel, true
	}
	if version == pkg.Latest && pkg.Latest != "" {
		if rel, ok := pkg.Versions[pkg.Latest]; ok {
			return pkg, rel, true
		}
	}
	return pkg, InternalRelease{}, false
}

func lowerName(s string) string {
	b := []byte(s)
	for i := 0; i < len(b); i++ {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 'a' - 'A'
		}
	}
	return string(b)
}
