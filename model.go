// This file defines the stable JSON/report domain model for the pre-install
// dependency-confusion checker. The checker separates public packages from
// internal namespaces using explicit configuration instead of guessing: only
// names that match a declared internal prefix/exact reservation, or sources
// that diverge from declared registries, produce findings. Ordinary external
// packages resolved from a declared public registry or mirror are never
// flagged.
package main

import "time"

// Rule identifiers are stable and part of the JSON/CLI contract.
const (
	// RuleUndeclaredMirror (DG101 / 未声明镜像): a resolved source points at a
	// registry/mirror host that is not present in the declared registry list.
	RuleUndeclaredMirror = "DG101"

	// RulePublicSameName (DG102 / 同名公共包): a name reserved as internal also
	// exists in the public registry catalog fixture.
	RulePublicSameName = "DG102"

	// RuleInternalPrefixFallback (DG103 / 内部前缀回退): a package under a
	// declared internal prefix/scope is resolved through the public registry
	// because of a fallback/miss path, or that fallback is enabled.
	RuleInternalPrefixFallback = "DG103"

	// RuleLockfileOverride (DG104 / 锁文件覆盖): a lockfile entry overrides the
	// source registry or the sha256 content digest prescribed by configuration
	// and the internal index for a protected package.
	RuleLockfileOverride = "DG104"
)

// Severity is the finding severity.
type Severity string

const (
	SeverityError   Severity = "error"
	SeverityWarning Severity = "warning"
	SeverityInfo    Severity = "info"
)

// RegistryKind classifies a declared registry.
type RegistryKind string

const (
	RegistryInternal RegistryKind = "internal"
	RegistryPublic   RegistryKind = "public"
	RegistryMirror   RegistryKind = "mirror"
)

// Registry is a declared package source. Every registry/mirror that an
// install is allowed to use must be listed here.
type Registry struct {
	ID      string       `json:"id"`
	URL     string       `json:"url"`
	Kind    RegistryKind `json:"kind"`
	Default bool         `json:"default,omitempty"`
}

// NamespacePolicy declares which package names are internal and how misses
// are handled. Fallback must be "deny" for a protected namespace; "public"
// enables the dangerous internal-prefix -> public-registry fallback.
type NamespacePolicy struct {
	InternalRegistryID string   `json:"internal_registry_id,omitempty"`
	Prefixes           []string `json:"prefixes,omitempty"`
	Exact              []string `json:"exact,omitempty"`
	Fallback           string   `json:"fallback,omitempty"` // "deny" (default) or "public"
}

// Config is the depguard configuration document (depguard.json).
type Config struct {
	Schema  string `json:"schema,omitempty"`
	Project string `json:"project,omitempty"`

	Manifest string `json:"manifest,omitempty"`
	Lockfile string `json:"lockfile,omitempty"`
	// Npmrc optionally points at a real .npmrc whose registry and
	// "<scope>:registry" lines are merged into the declared sources.
	Npmrc string `json:"npmrc,omitempty"`

	PublicCatalog string `json:"public_catalog,omitempty"`
	InternalIndex string `json:"internal_index,omitempty"`

	Registries []Registry      `json:"registries"`
	Namespace  NamespacePolicy `json:"namespace"`

	// TrustedPublicPackages lists vetted open-source packages. They are never
	// treated as internal collisions; the list is also consumed by registry
	// curation. It is intentionally not required for precision.
	TrustedPublicPackages []string `json:"trusted_public_packages,omitempty"`

	// RootDir is the directory used to resolve relative fixture paths. It is
	// not serialized from JSON meaningfully on input.
	RootDir string `json:"-"`
}

// Dependency is one normalized manifest dependency.
type Dependency struct {
	Name string `json:"name"`
	Spec string `json:"spec,omitempty"`
	Dev  bool   `json:"dev,omitempty"`
}

// Manifest is a normalized project manifest.
type Manifest struct {
	Dependencies []Dependency `json:"dependencies"`
}

// LockEntry is one normalized locked resolution.
type LockEntry struct {
	Name            string `json:"name"`
	Version         string `json:"version,omitempty"`
	Resolved        string `json:"resolved,omitempty"`
	Integrity       string `json:"integrity,omitempty"`
	RegistryID      string `json:"registry_id,omitempty"`
	ViaFallback     bool   `json:"via_fallback,omitempty"`
	SelectionReason string `json:"selection_reason,omitempty"`
}

// Lockfile is a normalized lockfile.
type Lockfile struct {
	Format  string      `json:"format,omitempty"`
	Entries []LockEntry `json:"entries"`
}

// PublicPackage is the local-fixture view of a package on the public registry.
type PublicPackage struct {
	Name     string   `json:"name"`
	Latest   string   `json:"latest_version,omitempty"`
	Versions []string `json:"versions,omitempty"`
	Registry string   `json:"registry,omitempty"`
}

// PublicCatalog is an offline fixture of public-registry metadata.
type PublicCatalog struct {
	Registry string                   `json:"registry,omitempty"`
	Packages map[string]PublicPackage `json:"packages"`
}

// InternalRelease is one published internal version.
type InternalRelease struct {
	Version string `json:"version"`
	SHA256  string `json:"sha256,omitempty"`
	Tarball string `json:"tarball,omitempty"`
	// Archive is a local tar path (relative to the index file) used by
	// `depguard seed` to populate a registry from local fixtures.
	Archive string `json:"archive,omitempty"`
}

// InternalPackage groups internal releases.
type InternalPackage struct {
	Name     string                     `json:"name"`
	Latest   string                     `json:"latest,omitempty"`
	Versions map[string]InternalRelease `json:"versions,omitempty"`
}

// InternalIndex is the trusted index of the internal registry, used to derive
// verified replacement candidates and expected digests.
type InternalIndex struct {
	Registry string                     `json:"registry,omitempty"`
	Packages map[string]InternalPackage `json:"packages"`
}

// SourceCandidate is a proposed safe source to use in place of a risky one.
type SourceCandidate struct {
	Kind       RegistryKind `json:"kind,omitempty"`
	RegistryID string       `json:"registry_id,omitempty"`
	SourceURL  string       `json:"source_url"`
	Version    string       `json:"version,omitempty"`
	SHA256     string       `json:"sha256,omitempty"`
	Available  bool         `json:"available"`
	Verified   bool         `json:"verified"`
	Note       string       `json:"note,omitempty"`
}

// Finding is one detected configuration risk.
type Finding struct {
	RuleID        string            `json:"rule_id"`
	Rule          string            `json:"rule"`
	Title         string            `json:"title"`
	TitleZH       string            `json:"title_zh"`
	Severity      Severity          `json:"severity"`
	Package       string            `json:"package,omitempty"`
	Version       string            `json:"version,omitempty"`
	MatchedPrefix string            `json:"matched_prefix,omitempty"`
	Message       string            `json:"message"`
	Evidence      map[string]string `json:"evidence,omitempty"`

	// ReplacedSource is the current risky source that would be replaced
	// before install ("被替换的来源").
	ReplacedSource string `json:"replaced_source,omitempty"`

	// Candidate is the safe replacement source ("候选替换来源").
	Candidate *SourceCandidate `json:"candidate_source,omitempty"`

	Recommendation string `json:"recommendation,omitempty"`
}

// SourceReplacement groups the concrete source swap for one locked package.
type SourceReplacement struct {
	Package        string          `json:"package"`
	Version        string          `json:"version,omitempty"`
	ReplacedSource string          `json:"replaced_source"`
	Candidate      SourceCandidate `json:"candidate_source"`
	FindingIDs     []string        `json:"finding_ids"`
}

// Summary counts report findings.
type Summary struct {
	ScannedPackages int            `json:"scanned_packages"`
	Total           int            `json:"total"`
	Errors          int            `json:"errors"`
	Warnings        int            `json:"warnings"`
	ByRule          map[string]int `json:"by_rule"`
}

// Report is the checker result and the stable JSON contract.
type Report struct {
	Schema       string              `json:"schema"`
	GeneratedAt  time.Time           `json:"generated_at"`
	Project      string              `json:"project,omitempty"`
	OK           bool                `json:"ok"`
	Summary      Summary             `json:"summary"`
	Findings     []Finding           `json:"findings"`
	Replacements []SourceReplacement `json:"replacements"`
}
