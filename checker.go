package main

import (
	"context"
	"sort"
	"strings"
	"time"
)

// Checker runs the four dependency-confusion configuration checks.
type Checker struct {
	cfg        *Config
	manifest   *Manifest
	lock       *Lockfile
	public     *PublicCatalog
	internal   *InternalIndex
	resolver   CandidateResolver
	regs       *registryIndex
	classifier *Classifier
	now        func() time.Time
}

// Option customizes a Checker.
type Option func(*Checker)

// WithResolver overrides the internal candidate resolver (e.g. HTTPResolver).
func WithResolver(r CandidateResolver) Option {
	return func(c *Checker) { c.resolver = r }
}

// WithClock overrides the report clock (tests).
func WithClock(now func() time.Time) Option {
	return func(c *Checker) { c.now = now }
}

// NewChecker builds a Checker from loaded documents.
func NewChecker(cfg *Config, mf *Manifest, lf *Lockfile, pub *PublicCatalog, idx *InternalIndex, opts ...Option) *Checker {
	if mf == nil {
		mf = &Manifest{}
	}
	if lf == nil {
		lf = &Lockfile{}
	}
	if pub == nil {
		pub = &PublicCatalog{Packages: map[string]PublicPackage{}}
	}
	if idx == nil {
		idx = &InternalIndex{Packages: map[string]InternalPackage{}}
	}
	c := &Checker{
		cfg:        cfg,
		manifest:   mf,
		lock:       lf,
		public:     pub,
		internal:   idx,
		regs:       newRegistryIndex(cfg.Registries),
		classifier: NewClassifier(cfg.Namespace),
		now:        time.Now,
	}
	c.resolver = StaticIndexResolver{Index: idx, RegistryBase: c.internalBase()}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

func (c *Checker) internalBase() string {
	if r := c.regs.Internal(c.cfg.Namespace); r != nil {
		return r.URL
	}
	return c.internal.Registry
}

// CheckConfigFile loads a config and all referenced fixtures and runs Check.
func CheckConfigFile(ctx context.Context, configPath string) (*Report, error) {
	cfg, err := LoadConfig(configPath)
	if err != nil {
		return nil, err
	}
	if p := cfg.ResolvePath(cfg.Npmrc); p != "" {
		rc, err := LoadNpmrc(p)
		if err != nil {
			return nil, err
		}
		cfg.Registries = mergeRegistries(cfg.Registries, rc.Registries(cfg.Namespace, cfg.Registries))
	}
	mf := &Manifest{}
	if p := cfg.ResolvePath(cfg.Manifest); p != "" {
		mf, err = LoadManifestFile(p)
		if err != nil {
			return nil, err
		}
	}
	lf := &Lockfile{}
	if p := cfg.ResolvePath(cfg.Lockfile); p != "" {
		lf, err = LoadLockfileFile(p)
		if err != nil {
			return nil, err
		}
	}
	pub, err := LoadPublicCatalog(cfg.ResolvePath(cfg.PublicCatalog))
	if err != nil {
		return nil, err
	}
	idx, err := LoadInternalIndex(cfg.ResolvePath(cfg.InternalIndex))
	if err != nil {
		return nil, err
	}
	return NewChecker(cfg, mf, lf, pub, idx).Check(ctx)
}

type resolvedPackage struct {
	name   string
	entry  LockEntry
	inLock bool
}

// Check runs every rule and assembles the report including the replacement
// plan. It never returns an error for findings; the error return is reserved
// for context/resolver failures that prevent the check.
func (c *Checker) Check(ctx context.Context) (*Report, error) {
	report := &Report{
		Schema:       "depguard.report/v1",
		GeneratedAt:  c.now().UTC(),
		Project:      c.cfg.Project,
		Findings:     []Finding{},
		Replacements: []SourceReplacement{},
		Summary:      Summary{ByRule: map[string]int{}},
	}

	pkgs := c.mergedPackages()
	report.Summary.ScannedPackages = len(pkgs)

	// Configuration-level DG103: the namespace policy itself allows the
	// internal-prefix -> public fallback.
	if c.classifier.FallbackPublic() {
		info := ruleInfo(RuleInternalPrefixFallback)
		report.Findings = append(report.Findings, Finding{
			RuleID: info.ID, Rule: info.Slug, Title: info.TitleEN, TitleZH: info.TitleZH,
			Severity:       SeverityWarning,
			Message:        "namespace policy sets fallback=\"public\"; a miss in the internal registry for a reserved prefix is allowed to resolve from the public registry, enabling dependency confusion",
			Evidence:       map[string]string{"fallback": "public", "prefixes": strings.Join(c.cfg.Namespace.Prefixes, ",")},
			Recommendation: "Set namespace.fallback=\"deny\" and reserve/publish internal names; never forward reserved prefixes to a public registry.",
		})
	}

	for _, p := range pkgs {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		findings, err := c.checkPackage(ctx, p)
		if err != nil {
			return nil, err
		}
		report.Findings = append(report.Findings, findings...)
	}

	c.buildReplacements(report)
	c.summarize(report)
	return report, nil
}

// mergedPackages unions lock entries (including transitive) with manifest
// direct dependencies. Lock data wins when both exist.
func (c *Checker) mergedPackages() []resolvedPackage {
	byName := map[string]resolvedPackage{}
	order := []string{}

	for _, e := range c.lock.Entries {
		if _, seen := byName[e.Name]; !seen {
			order = append(order, e.Name)
		}
		byName[e.Name] = resolvedPackage{name: e.Name, entry: e, inLock: true}
	}
	for _, d := range c.manifest.Dependencies {
		if existing, seen := byName[d.Name]; seen {
			if existing.entry.Version == "" && d.Spec != "" {
				e := existing.entry
				e.Version = d.Spec
				existing.entry = e
				byName[d.Name] = existing
			}
			continue
		}
		order = append(order, d.Name)
		byName[d.Name] = resolvedPackage{name: d.Name, entry: LockEntry{Name: d.Name, Version: d.Spec}, inLock: false}
	}

	out := make([]resolvedPackage, 0, len(order))
	for _, name := range order {
		out = append(out, byName[name])
	}
	return out
}

func (c *Checker) summarize(r *Report) {
	r.Summary.Total = len(r.Findings)
	for _, f := range r.Findings {
		r.Summary.ByRule[f.RuleID]++
		switch f.Severity {
		case SeverityError:
			r.Summary.Errors++
		case SeverityWarning:
			r.Summary.Warnings++
		}
	}
	r.OK = r.Summary.Errors == 0

	sort.SliceStable(r.Findings, func(i, j int) bool {
		if r.Findings[i].RuleID != r.Findings[j].RuleID {
			return r.Findings[i].RuleID < r.Findings[j].RuleID
		}
		return r.Findings[i].Package < r.Findings[j].Package
	})
}

func (c *Checker) buildReplacements(r *Report) {
	type key struct{ pkg, ver, src string }
	idx := map[key]*SourceReplacement{}
	for _, f := range r.Findings {
		if f.Candidate == nil || f.ReplacedSource == "" {
			continue
		}
		k := key{f.Package, f.Version, f.ReplacedSource}
		rep, ok := idx[k]
		if !ok {
			cand := *f.Candidate
			rep = &SourceReplacement{
				Package:        f.Package,
				Version:        f.Version,
				ReplacedSource: f.ReplacedSource,
				Candidate:      cand,
			}
			idx[k] = rep
		}
		rep.FindingIDs = appendIfMissing(rep.FindingIDs, f.RuleID)
		// Prefer a verified internal candidate.
		if f.Candidate.Verified && !rep.Candidate.Verified {
			rep.Candidate = *f.Candidate
		}
	}
	// Rebuild slice from pointer map to retain FindingIDs mutations.
	r.Replacements = r.Replacements[:0]
	keys := make([]key, 0, len(idx))
	for k := range idx {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].pkg != keys[j].pkg {
			return keys[i].pkg < keys[j].pkg
		}
		return keys[i].src < keys[j].src
	})
	for _, k := range keys {
		rep := idx[k]
		sort.Strings(rep.FindingIDs)
		r.Replacements = append(r.Replacements, *rep)
	}
}

func appendIfMissing(xs []string, s string) []string {
	for _, x := range xs {
		if x == s {
			return xs
		}
	}
	return append(xs, s)
}

func containsFallbackReason(reason string) bool {
	r := strings.ToLower(reason)
	return strings.Contains(r, "fallback") || strings.Contains(r, "404") || strings.Contains(r, "miss")
}
