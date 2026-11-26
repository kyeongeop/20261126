package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// LoadManifestFile reads either the normalized manifest shape or an npm
// package.json (dependencies/devDependencies as name->range maps).
func LoadManifestFile(filename string) (*Manifest, error) {
	b, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("read manifest: %w", err)
	}
	return ParseManifest(b)
}

// ParseManifest parses manifest bytes.
func ParseManifest(b []byte) (*Manifest, error) {
	var probe struct {
		Dependencies    json.RawMessage `json:"dependencies"`
		DevDependencies json.RawMessage `json:"devDependencies"`
	}
	if err := json.Unmarshal(b, &probe); err != nil {
		return nil, fmt.Errorf("parse manifest: %w", err)
	}

	mf := &Manifest{}

	// Normalized form: dependencies is an array of {name,spec}.
	if deps, ok := parseDependencyList(probe.Dependencies); ok {
		mf.Dependencies = append(mf.Dependencies, deps...)
	} else if deps, ok := parseDependencyMap(probe.Dependencies, false); ok {
		mf.Dependencies = append(mf.Dependencies, deps...)
	}
	if deps, ok := parseDependencyMap(probe.DevDependencies, true); ok {
		mf.Dependencies = append(mf.Dependencies, deps...)
	} else if deps, ok := parseDependencyList(probe.DevDependencies); ok {
		for i := range deps {
			deps[i].Dev = true
		}
		mf.Dependencies = append(mf.Dependencies, deps...)
	}
	return mf, nil
}

func parseDependencyList(raw json.RawMessage) ([]Dependency, bool) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, false
	}
	var deps []Dependency
	if err := json.Unmarshal(raw, &deps); err != nil {
		return nil, false
	}
	return deps, true
}

func parseDependencyMap(raw json.RawMessage, dev bool) ([]Dependency, bool) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, false
	}
	var m map[string]string
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, false
	}
	out := make([]Dependency, 0, len(m))
	for name, spec := range m {
		out = append(out, Dependency{Name: name, Spec: spec, Dev: dev})
	}
	return out, true
}

// LoadLockfileFile reads a normalized lockfile or an npm package-lock.json.
func LoadLockfileFile(filename string) (*Lockfile, error) {
	b, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("read lockfile: %w", err)
	}
	return ParseLockfile(b)
}

type normalizedProbe struct {
	Entries []LockEntry `json:"entries"`
}

// ParseLockfile parses normalized {"entries":[...]} or npm package-lock v1-3.
func ParseLockfile(b []byte) (*Lockfile, error) {
	var keyProbe map[string]json.RawMessage
	if err := json.Unmarshal(b, &keyProbe); err != nil {
		return nil, fmt.Errorf("parse lockfile: %w", err)
	}
	if raw, has := keyProbe["entries"]; has {
		var lf Lockfile
		if err := json.Unmarshal(b, &lf); err != nil {
			return nil, fmt.Errorf("parse normalized lockfile: %w", err)
		}
		_ = raw
		if lf.Entries == nil {
			lf.Entries = []LockEntry{}
		}
		if lf.Format == "" {
			lf.Format = "normalized"
		}
		return &lf, nil
	}

	lf := &Lockfile{Format: "npm-package-lock"}

	if pkgsRaw, ok := keyProbe["packages"]; ok {
		var pkgs map[string]npmLockNode
		if err := json.Unmarshal(pkgsRaw, &pkgs); err == nil {
			for key, node := range pkgs {
				name := nameFromNodeModulesKey(key)
				if name == "" {
					continue
				}
				lf.Entries = append(lf.Entries, node.toEntry(name))
			}
		}
	}

	if depsRaw, ok := keyProbe["dependencies"]; ok {
		var deps map[string]npmLockNode
		if err := json.Unmarshal(depsRaw, &deps); err == nil {
			walkNpmDeps(deps, &lf.Entries)
		}
	}

	return lf, nil
}

type npmLockNode struct {
	Version         string                 `json:"version"`
	Resolved        string                 `json:"resolved"`
	Integrity       string                 `json:"integrity"`
	ViaFallback     bool                   `json:"via_fallback"`
	SelectionReason string                 `json:"selection_reason"`
	Dependencies    map[string]npmLockNode `json:"dependencies"`
}

func (n npmLockNode) toEntry(name string) LockEntry {
	return LockEntry{
		Name:            name,
		Version:         n.Version,
		Resolved:        n.Resolved,
		Integrity:       n.Integrity,
		ViaFallback:     n.ViaFallback,
		SelectionReason: n.SelectionReason,
	}
}

func walkNpmDeps(deps map[string]npmLockNode, entries *[]LockEntry) {
	for name, node := range deps {
		*entries = append(*entries, node.toEntry(name))
		if len(node.Dependencies) > 0 {
			walkNpmDeps(node.Dependencies, entries)
		}
	}
}

// nameFromNodeModulesKey maps "node_modules/@scope/name" or a nested key to
// the package name. Empty string marks the project root / non-package key.
func nameFromNodeModulesKey(key string) string {
	if key == "" {
		return ""
	}
	const marker = "node_modules/"
	idx := strings.LastIndex(key, marker)
	if idx < 0 {
		return ""
	}
	name := key[idx+len(marker):]
	if name == "" || strings.HasPrefix(name, ".") {
		return ""
	}
	return name
}
