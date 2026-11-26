package main

// Guard is the dependency-confusion protection policy for the internal
// registry. Reserved internal names are never forwarded/fallen back to a
// public registry, even when the internal copy is missing.
type Guard struct {
	Classifier *Classifier
	Public     *PublicCatalog

	// AllowPublicFallback enables forwarding for *unreserved* names only.
	// It defaults to false so the registry is internal-only. Reserved
	// names are blocked from public fallback regardless of this value.
	AllowPublicFallback bool

	// CuratedPublic is an explicit allowlist of vetted open-source packages
	// that may be served/proxied. When non-empty it further restricts
	// unreserved access.
	CuratedPublic map[string]bool
}

// GuardAction is the resolved handling decision.
type GuardAction string

const (
	ActionServeInternal GuardAction = "serve-internal"
	ActionBlockReserved GuardAction = "blocked-reserved-no-public-fallback"
	ActionPublicAllowed GuardAction = "public-allowed"
	ActionDeny          GuardAction = "deny-unmanaged-public"
)

// Decision explains how the registry treats a name.
type Decision struct {
	Name              string      `json:"name"`
	Internal          bool        `json:"internal"`
	MatchedPrefix     string      `json:"matched_prefix,omitempty"`
	Action            GuardAction `json:"action"`
	PublicHasSameName bool        `json:"public_has_same_name"`
	Reason            string      `json:"reason"`
}

// Evaluate applies the protection policy to name.
func (g *Guard) Evaluate(name string) Decision {
	d := Decision{Name: name}
	if g.Public != nil {
		d.PublicHasSameName = g.Public.Has(name)
	}

	match := g.Classifier.Match(name)
	d.Internal = match.Internal
	d.MatchedPrefix = match.MatchedPrefix

	if match.Internal {
		// Reserved namespace: always internal-only. A missing internal
		// release must be published, never substituted from public.
		d.Action = ActionBlockReserved
		d.Reason = "name belongs to a reserved internal namespace; public-registry fallback is disabled"
		return d
	}

	if len(g.CuratedPublic) > 0 {
		if g.CuratedPublic[name] {
			d.Action = ActionPublicAllowed
			d.Reason = "package is on the curated public allowlist"
			return d
		}
		d.Action = ActionDeny
		d.Reason = "package is not internal and not on the curated public allowlist"
		return d
	}

	if g.AllowPublicFallback {
		d.Action = ActionPublicAllowed
		d.Reason = "unreserved package may use the explicit public fallback"
		return d
	}

	d.Action = ActionDeny
	d.Reason = "unmanaged public package is not hosted and public fallback is disabled"
	return d
}

// AllowsUpstream reports whether an upstream/public fetch is permitted for
// name. Reserved names always return false, which is the core protection.
func (g *Guard) AllowsUpstream(name string) bool {
	d := g.Evaluate(name)
	return d.Action == ActionPublicAllowed
}
