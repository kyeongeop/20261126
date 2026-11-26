package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
)

// Npmrc is the small subset of .npmrc that decides where packages resolve.
type Npmrc struct {
	DefaultRegistry string
	Scoped          map[string]string // scope (e.g. "@acme") -> registry URL
}

// LoadNpmrc reads and parses an .npmrc file.
func LoadNpmrc(filename string) (*Npmrc, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("read npmrc: %w", err)
	}
	defer f.Close()
	return ParseNpmrc(f)
}

// ParseNpmrc parses registry= and @scope:registry= lines. Auth tokens and all
// other ini keys are ignored.
func ParseNpmrc(r io.Reader) (*Npmrc, error) {
	rc := &Npmrc{Scoped: map[string]string{}}
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		idx := strings.IndexByte(line, '=')
		if idx < 0 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		val := strings.TrimSpace(line[idx+1:])
		val = strings.Trim(val, `"'`)
		switch {
		case key == "registry":
			rc.DefaultRegistry = val
		case strings.HasSuffix(key, ":registry"):
			scope := strings.TrimSpace(strings.TrimSuffix(key, ":registry"))
			if scope != "" && val != "" {
				rc.Scoped[scope] = val
			}
		}
	}
	return rc, sc.Err()
}

// Registries converts .npmrc directives into declared Registry values. URLs
// matching the configured internal registry are treated as internal; the
// default registry is public; scoped entries are declared scoped mirrors.
func (n *Npmrc) Registries(policy NamespacePolicy, existing []Registry) []Registry {
	var out []Registry
	internalURL := ""
	if r := newRegistryIndex(existing).Internal(policy); r != nil {
		internalURL = normalizeBase(r.URL)
	}

	if n.DefaultRegistry != "" {
		kind := RegistryPublic
		if normalizeBase(n.DefaultRegistry) == internalURL {
			kind = RegistryInternal
		}
		out = append(out, Registry{ID: "npmrc-default", URL: n.DefaultRegistry, Kind: kind, Default: true})
	}
	scopes := make([]string, 0, len(n.Scoped))
	for s := range n.Scoped {
		scopes = append(scopes, s)
	}
	for _, scope := range scopes {
		u := n.Scoped[scope]
		kind := RegistryMirror
		if normalizeBase(u) == internalURL {
			kind = RegistryInternal
		}
		id := "npmrc-scope-" + strings.TrimPrefix(scope, "@")
		out = append(out, Registry{ID: id, URL: u, Kind: kind})
	}
	return out
}

// mergeRegistries appends additions unless an equivalent normalized URL is
// already declared. Existing entries win so their id/kind are preserved.
func mergeRegistries(existing, additions []Registry) []Registry {
	seen := map[string]bool{}
	for _, r := range existing {
		seen[normalizeBase(r.URL)] = true
	}
	for _, r := range additions {
		key := normalizeBase(r.URL)
		if key == "" || seen[key] {
			continue
		}
		seen[key] = true
		existing = append(existing, r)
	}
	return existing
}
