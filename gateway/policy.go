package gateway

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// UnknownPolicy controls what happens when neither an exact route nor a
// wildcard route matches the SNI value.
type UnknownPolicy string

const (
	// UnknownPolicyReject aborts the TLS handshake.
	UnknownPolicyReject UnknownPolicy = "reject"
	// UnknownPolicyDefault serves the configured default certificate.
	UnknownPolicyDefault UnknownPolicy = "default"
)

// MatchKind describes how a certificate was selected for SNI.
type MatchKind string

const (
	MatchExact    MatchKind = "exact"
	MatchWildcard MatchKind = "wildcard"
	MatchDefault  MatchKind = "default"
	MatchRejected MatchKind = "rejected"
)

// Selection is the complete, immutable result of one SNI lookup.
type Selection struct {
	ServerName      string
	Kind            MatchKind
	Pattern         string
	CertificateName string
	Certificate     *Certificate
	Reason          string
}

// Selected reports whether the selection produced a certificate.
func (s Selection) Selected() bool {
	return s.Certificate != nil
}

type route struct {
	host        string
	wildcard    bool
	suffix      string
	certificate *Certificate
}

// Snapshot is an immutable routing table. A connection keeps the snapshot it
// observed when the TCP connection was accepted for its entire handshake.
type Snapshot struct {
	generation         uint64
	loadedAt           time.Time
	unknownPolicy      UnknownPolicy
	exact              map[string]*route
	wildcards          []*route
	defaultCertificate *Certificate
}

// Generation is the monotonic store generation that published this snapshot.
func (s *Snapshot) Generation() uint64 {
	if s == nil {
		return 0
	}
	return s.generation
}

// LoadedAt is the time this snapshot was built from its configuration file.
func (s *Snapshot) LoadedAt() time.Time {
	if s == nil {
		return time.Time{}
	}
	return s.loadedAt
}

// UnknownPolicy returns the policy for unmatched SNI values.
func (s *Snapshot) UnknownPolicy() UnknownPolicy {
	if s == nil {
		return UnknownPolicyReject
	}
	return s.unknownPolicy
}

// Resolve applies this priority: exact host, wildcard host, then the
// configured unknown-SNI policy (default certificate or rejected handshake).
func (s *Snapshot) Resolve(serverName string) Selection {
	name := normalizeServerName(serverName)
	if s == nil {
		return Selection{ServerName: name, Kind: MatchRejected, Reason: "no_snapshot"}
	}

	if name != "" {
		if matched := s.exact[name]; matched != nil {
			return selectionFor(name, MatchExact, matched.host, matched.certificate, "exact_match")
		}
		for _, matched := range s.wildcards {
			if wildcardMatches(matched.suffix, name) {
				return selectionFor(name, MatchWildcard, matched.host, matched.certificate, "wildcard_match")
			}
		}
	}

	reason := "unknown_server_name"
	if name == "" {
		reason = "missing_server_name"
	}
	if s.unknownPolicy == UnknownPolicyDefault && s.defaultCertificate != nil {
		return selectionFor(name, MatchDefault, "", s.defaultCertificate, reason+"_default")
	}
	return Selection{ServerName: name, Kind: MatchRejected, Reason: reason + "_reject"}
}

func selectionFor(name string, kind MatchKind, pattern string, cert *Certificate, reason string) Selection {
	selection := Selection{
		ServerName:  name,
		Kind:        kind,
		Pattern:     pattern,
		Reason:      reason,
		Certificate: cert,
	}
	if cert != nil {
		selection.CertificateName = cert.Name
	}
	return selection
}

func normalizeServerName(serverName string) string {
	name := strings.ToLower(strings.TrimSpace(serverName))
	name = strings.TrimSuffix(name, ".")
	return name
}

func normalizePattern(pattern string) (host string, wildcard bool, suffix string, err error) {
	host = normalizeServerName(pattern)
	if host == "" {
		return "", false, "", fmt.Errorf("host pattern must not be empty")
	}
	if strings.ContainsAny(host, " \t\r\n/\\") {
		return "", false, "", fmt.Errorf("host pattern %q contains invalid characters", pattern)
	}

	switch {
	case !strings.Contains(host, "*"):
		return host, false, "", nil
	case strings.HasPrefix(host, "*.") && strings.Count(host, "*") == 1:
		suffix = host[1:]
		if strings.HasPrefix(suffix, "..") || strings.HasSuffix(suffix, ".") || strings.ContainsAny(suffix, "*") {
			return "", false, "", fmt.Errorf("invalid wildcard host pattern %q", pattern)
		}
		return host, true, suffix, nil
	default:
		return "", false, "", fmt.Errorf("wildcard host pattern %q must use exactly one leading '*.'", pattern)
	}
}

func wildcardMatches(suffix, serverName string) bool {
	if !strings.HasSuffix(serverName, suffix) {
		return false
	}
	label := strings.TrimSuffix(serverName, suffix)
	return label != "" && !strings.Contains(label, ".")
}

func sortWildcards(routes []*route) {
	sort.Slice(routes, func(i, j int) bool {
		if len(routes[i].suffix) != len(routes[j].suffix) {
			return len(routes[i].suffix) > len(routes[j].suffix)
		}
		return routes[i].host < routes[j].host
	})
}
