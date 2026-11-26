package main

import (
	"context"
	"strings"
)

func (c *Checker) newFinding(ruleID string) Finding {
	info := ruleInfo(ruleID)
	return Finding{
		RuleID:   info.ID,
		Rule:     info.Slug,
		Title:    info.TitleEN,
		TitleZH:  info.TitleZH,
		Severity: info.DefaultSev,
		Evidence: map[string]string{},
	}
}

func (c *Checker) checkPackage(ctx context.Context, p resolvedPackage) ([]Finding, error) {
	name := p.name
	e := p.entry
	match := c.classifier.Match(name)
	anchored := c.regs.Anchor(e.Resolved)

	var out []Finding

	// DG101: resolved source host is not a declared registry/mirror.
	if e.Resolved != "" && anchored == nil {
		f := c.newFinding(RuleUndeclaredMirror)
		f.Package = name
		f.Version = e.Version
		f.ReplacedSource = e.Resolved
		f.Message = "resolved source uses a registry/mirror that is not declared in configuration"
		f.Evidence["resolved"] = e.Resolved
		f.Evidence["host"] = HostOf(e.Resolved)
		f.Evidence["declared_registries"] = c.declaredHosts()
		if match.Internal {
			cand, err := c.resolver.InternalCandidate(ctx, name, exactOrEmpty(e.Version))
			if err != nil {
				return nil, err
			}
			f.Candidate = cand
			f.Recommendation = "Remove the undeclared mirror source and resolve this reserved internal package from the declared internal registry, pinning its sha256."
		} else {
			f.Candidate = c.publicCandidate(name, e.Version)
			f.Recommendation = "Declare and approve this mirror (with integrity pinning) or repoint the lockfile at the declared public registry; do not consume external packages from an unapproved host."
		}
		out = append(out, f)
	}

	// DG102: an internal/reserved name also exists on the public registry.
	if match.Internal && c.public.Has(name) {
		pub, _ := c.public.Get(name)
		f := c.newFinding(RulePublicSameName)
		f.Package = name
		f.Version = e.Version
		f.MatchedPrefix = match.MatchedPrefix
		if f.MatchedPrefix == "" {
			f.Evidence["matched_exact"] = match.MatchedExact
		} else {
			f.Evidence["matched_prefix"] = match.MatchedPrefix
		}
		f.Message = "name is reserved as internal but the exact same package exists in the public registry, allowing dependency-confusion substitution"
		f.Evidence["public_latest"] = pub.Latest
		if pub.Registry != "" {
			f.Evidence["public_registry"] = pub.Registry
		} else if c.public.Registry != "" {
			f.Evidence["public_registry"] = c.public.Registry
		}
		if e.Resolved != "" {
			f.ReplacedSource = e.Resolved
		}
		cand, err := c.resolver.InternalCandidate(ctx, name, exactOrEmpty(e.Version))
		if err != nil {
			return nil, err
		}
		f.Candidate = cand
		f.Recommendation = "Reserve or remove the public squatting package, configure the name as internal-only, and install the verified internal candidate with a pinned sha256."
		out = append(out, f)
	}

	// DG103: internal prefix/scope resolved through a public fallback path.
	if match.Internal && match.MatchedPrefix != "" {
		viaMarker := e.ViaFallback || containsFallbackReason(e.SelectionReason)
		observedPublic := anchored != nil && anchored.Kind == RegistryPublic
		if viaMarker || observedPublic {
			f := c.newFinding(RuleInternalPrefixFallback)
			f.Package = name
			f.Version = e.Version
			f.MatchedPrefix = match.MatchedPrefix
			f.Message = "package under a declared internal prefix was resolved from the public registry via a miss/fallback path"
			f.Evidence["matched_prefix"] = match.MatchedPrefix
			f.Evidence["fallback_policy"] = c.cfg.Namespace.Fallback
			if e.SelectionReason != "" {
				f.Evidence["selection_reason"] = e.SelectionReason
			}
			if viaMarker {
				f.Evidence["via_fallback"] = "true"
			}
			if anchored != nil {
				f.Evidence["resolved_registry_id"] = anchored.ID
				f.Evidence["resolved_registry_kind"] = string(anchored.Kind)
			}
			if e.Resolved != "" {
				f.ReplacedSource = e.Resolved
			}
			cand, err := c.resolver.InternalCandidate(ctx, name, exactOrEmpty(e.Version))
			if err != nil {
				return nil, err
			}
			f.Candidate = cand
			f.Recommendation = "Disable public fallback for the prefix (namespace.fallback=\"deny\"), serve the name internally, and repoint the lockfile to the verified internal candidate."
			out = append(out, f)
		}
	}

	// DG104: lockfile overrides the expected source or digest of a protected
	// internal package.
	if match.Internal && p.inLock {
		internalReg := c.regs.Internal(c.cfg.Namespace)

		// Source-registry override.
		if e.Resolved != "" && internalReg != nil {
			wrongRegistry := anchored == nil || anchored.ID != internalReg.ID
			if wrongRegistry {
				f := c.newFinding(RuleLockfileOverride)
				f.Package = name
				f.Version = e.Version
				f.ReplacedSource = e.Resolved
				f.Message = "lockfile resolved source overrides the internal registry prescribed by configuration"
				f.Evidence["expected_registry_id"] = internalReg.ID
				f.Evidence["expected_registry_url"] = internalReg.URL
				if anchored != nil {
					f.Evidence["locked_registry_id"] = anchored.ID
				} else {
					f.Evidence["locked_host"] = HostOf(e.Resolved)
				}
				cand, err := c.resolver.InternalCandidate(ctx, name, exactOrEmpty(e.Version))
				if err != nil {
					return nil, err
				}
				f.Candidate = cand
				f.Recommendation = "Regenerate the lockfile against the internal registry and replace the overridden resolved URL with the candidate source."
				out = append(out, f)
			}
		}

		// Digest/integrity override against the trusted internal index.
		if lockDigest, ok := NormalizeSHA256(e.Integrity); ok {
			if _, rel, exists := c.internal.Release(name, exactOrEmpty(e.Version)); exists {
				trusted, ok2 := NormalizeSHA256(rel.SHA256)
				if ok2 && trusted != lockDigest {
					f := c.newFinding(RuleLockfileOverride)
					f.Package = name
					f.Version = rel.Version
					if e.Resolved != "" {
						f.ReplacedSource = e.Resolved
					}
					f.Message = "lockfile integrity overrides the sha256 published by the internal registry"
					f.Evidence["locked_integrity"] = lockDigest
					f.Evidence["internal_sha256"] = trusted
					cand, err := c.resolver.InternalCandidate(ctx, name, rel.Version)
					if err != nil {
						return nil, err
					}
					f.Candidate = cand
					f.Recommendation = "Replace the lockfile integrity with the internally published sha256 after confirming the resolved bytes; investigate possible tampering."
					out = append(out, f)
				}
			}
		}
	}

	return out, nil
}

func (c *Checker) declaredHosts() string {
	hosts := make([]string, 0, len(c.cfg.Registries))
	for _, r := range c.cfg.Registries {
		if h := HostOf(r.URL); h != "" {
			hosts = append(hosts, r.ID+"="+h)
		}
	}
	return strings.Join(hosts, ",")
}

// publicCandidate builds the declared-public equivalent source for an
// external package pulled through an undeclared mirror.
func (c *Checker) publicCandidate(name, version string) *SourceCandidate {
	reg := c.regs.Default()
	base := c.public.Registry
	id := ""
	kind := RegistryPublic
	if reg != nil {
		if base == "" {
			base = reg.URL
		}
		id = reg.ID
		kind = reg.Kind
	}
	v := exactOrEmpty(version)
	return &SourceCandidate{
		Kind:       kind,
		RegistryID: id,
		SourceURL:  publicTarballURL(base, name, v),
		Version:    v,
		Available:  true,
		Verified:   false,
		Note:       "repoint to the declared registry and pin its sha256 before install",
	}
}

// exactOrEmpty strips non-exact manifest ranges so they are not embedded into
// concrete candidate URLs.
func exactOrEmpty(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	if strings.ContainsAny(v, "^~*><| ") {
		return ""
	}
	return strings.TrimPrefix(v, "=")
}
