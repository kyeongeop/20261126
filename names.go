package main

import (
	"net/url"
	"strings"
)

// RuleInfo is human-readable metadata for a rule.
type RuleInfo struct {
	ID         string
	Slug       string
	TitleZH    string
	TitleEN    string
	DefaultSev Severity
}

// Rules documents the four checks in stable order. The Chinese names are the
// canonical labels from the requirement and must stay greppable.
var Rules = []RuleInfo{
	{RuleUndeclaredMirror, "undeclared-mirror", "未声明镜像", "Undeclared mirror/registry source", SeverityError},
	{RulePublicSameName, "same-name-public-package", "同名公共包", "Internal name also published on public registry", SeverityError},
	{RuleInternalPrefixFallback, "internal-prefix-fallback", "内部前缀回退", "Internal prefix falls back to public registry", SeverityError},
	{RuleLockfileOverride, "lockfile-source-override", "锁文件覆盖", "Lockfile overrides configured source or digest", SeverityError},
}

func ruleInfo(id string) RuleInfo {
	for _, r := range Rules {
		if r.ID == id {
			return r
		}
	}
	return RuleInfo{ID: id, Slug: "unknown", TitleZH: id, DefaultSev: SeverityWarning}
}

// NameMatch explains why a package name was classified.
type NameMatch struct {
	Internal      bool
	MatchedExact  string
	MatchedPrefix string
}

// Classifier decides whether a name belongs to the internal namespace using
// only explicit exact reservations and prefixes. It never treats an arbitrary
// external package as internal.
type Classifier struct {
	policy NamespacePolicy
	exact  map[string]string // lower-cased exact name -> original
}

// NewClassifier builds a Classifier from policy.
func NewClassifier(policy NamespacePolicy) *Classifier {
	c := &Classifier{policy: policy, exact: map[string]string{}}
	for _, name := range policy.Exact {
		n := strings.TrimSpace(name)
		if n == "" {
			continue
		}
		c.exact[strings.ToLower(n)] = n
	}
	return c
}

// Match classifies name. Exact reservations take precedence over prefixes.
func (c *Classifier) Match(name string) NameMatch {
	n := strings.TrimSpace(name)
	if original, ok := c.exact[strings.ToLower(n)]; ok {
		return NameMatch{Internal: true, MatchedExact: original}
	}
	for _, prefix := range c.policy.Prefixes {
		p := strings.TrimSpace(prefix)
		if p == "" {
			continue
		}
		if strings.HasPrefix(n, p) {
			return NameMatch{Internal: true, MatchedPrefix: p}
		}
	}
	return NameMatch{}
}

// IsInternal reports whether name is reserved as internal.
func (c *Classifier) IsInternal(name string) bool {
	return c.Match(name).Internal
}

// FallbackPublic reports whether the policy permits internal-prefix misses to
// fall through to the public registry. Anything other than explicit "public"
// is treated as the safe default "deny".
func (c *Classifier) FallbackPublic() bool {
	return strings.EqualFold(strings.TrimSpace(c.policy.Fallback), "public")
}

// registryIndex anchors absolute source URLs to declared registries.
type registryIndex struct {
	entries []Registry
	bases   []string // normalized URL without trailing "/"
}

func newRegistryIndex(regs []Registry) *registryIndex {
	idx := &registryIndex{entries: regs}
	for _, r := range regs {
		idx.bases = append(idx.bases, normalizeBase(r.URL))
	}
	return idx
}

func normalizeBase(raw string) string {
	return strings.TrimRight(strings.TrimSpace(raw), "/")
}

// Anchor returns the longest-prefix declared registry that rawURL belongs to,
// or nil when the source uses an undeclared host/mirror.
func (idx *registryIndex) Anchor(rawURL string) *Registry {
	u := strings.TrimSpace(rawURL)
	if u == "" {
		return nil
	}
	parsed, err := url.Parse(u)
	if err != nil || parsed.Host == "" {
		return nil
	}
	best := -1
	bestLen := -1
	for i := range idx.entries {
		base := idx.bases[i]
		if base == "" {
			continue
		}
		bp, err := url.Parse(base)
		if err != nil || bp.Host == "" {
			continue
		}
		if !strings.EqualFold(parsed.Host, bp.Host) {
			continue
		}
		basePath := strings.TrimRight(bp.EscapedPath(), "/")
		srcPath := parsed.EscapedPath()
		if basePath != "" {
			if srcPath != basePath && !strings.HasPrefix(srcPath, basePath+"/") {
				continue
			}
		}
		if len(base) > bestLen {
			bestLen = len(base)
			best = i
		}
	}
	if best < 0 {
		return nil
	}
	r := idx.entries[best]
	return &r
}

// ByID returns the declared registry with id.
func (idx *registryIndex) ByID(id string) *Registry {
	for i := range idx.entries {
		if idx.entries[i].ID == id {
			r := idx.entries[i]
			return &r
		}
	}
	return nil
}

// Default returns the configured default/public registry.
func (idx *registryIndex) Default() *Registry {
	for i := range idx.entries {
		if idx.entries[i].Default {
			r := idx.entries[i]
			return &r
		}
	}
	for i := range idx.entries {
		if idx.entries[i].Kind == RegistryPublic {
			r := idx.entries[i]
			return &r
		}
	}
	if len(idx.entries) > 0 {
		r := idx.entries[0]
		return &r
	}
	return nil
}

// Internal returns the registry designated as the internal registry.
func (idx *registryIndex) Internal(policy NamespacePolicy) *Registry {
	if id := strings.TrimSpace(policy.InternalRegistryID); id != "" {
		if r := idx.ByID(id); r != nil {
			return r
		}
	}
	for i := range idx.entries {
		if idx.entries[i].Kind == RegistryInternal {
			r := idx.entries[i]
			return &r
		}
	}
	return nil
}

// HostOf extracts a host for evidence/display.
func HostOf(rawURL string) string {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return ""
	}
	return u.Host
}

// tarballName builds the conventional "<base>-<version>.tgz" file name used in
// npm-style URLs. For scoped names ("@scope/name") the base is "name".
func tarballBaseName(name string) string {
	n := strings.TrimPrefix(name, "@")
	if i := strings.LastIndex(n, "/"); i >= 0 {
		n = n[i+1:]
	}
	return n
}

// publicTarballURL renders an npm-style public tarball URL for a package.
func publicTarballURL(base, name, version string) string {
	base = normalizeBase(base)
	if version == "" {
		return base + "/" + name
	}
	file := tarballBaseName(name) + "-" + version + ".tgz"
	return base + "/" + name + "/-/" + file
}

// internalTarballURL renders the protected registry's query endpoint.
func internalTarballURL(base, name, version string) string {
	base = normalizeBase(base)
	q := url.Values{}
	q.Set("name", name)
	if version != "" {
		q.Set("version", version)
	}
	return base + "/v1/tarball?" + q.Encode()
}

// releaseTarball picks an explicit tarball or derives the internal endpoint.
func releaseTarball(regBase string, rel InternalRelease, pkgName string) string {
	if strings.TrimSpace(rel.Tarball) != "" {
		return rel.Tarball
	}
	return internalTarballURL(regBase, pkgName, rel.Version)
}
