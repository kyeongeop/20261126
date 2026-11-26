package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// CandidateResolver supplies a verified internal replacement candidate.
type CandidateResolver interface {
	InternalCandidate(ctx context.Context, name, version string) (*SourceCandidate, error)
}

// StaticIndexResolver derives candidates from the trusted InternalIndex.
type StaticIndexResolver struct {
	Index *InternalIndex
	// RegistryBase overrides Index.Registry when building derived URLs.
	RegistryBase string
}

// InternalCandidate implements CandidateResolver.
func (r StaticIndexResolver) InternalCandidate(_ context.Context, name, version string) (*SourceCandidate, error) {
	base := r.RegistryBase
	if base == "" && r.Index != nil {
		base = r.Index.Registry
	}
	cand := &SourceCandidate{Kind: RegistryInternal, SourceURL: internalTarballURL(base, name, version), Version: version}
	if r.Index == nil {
		cand.Available = false
		cand.Note = "internal index unavailable; publish the reserved name before switching"
		return cand, nil
	}
	if _, rel, ok := r.Index.Release(name, version); ok {
		digest, _ := NormalizeSHA256(rel.SHA256)
		cand.Version = rel.Version
		cand.SHA256 = digest
		cand.SourceURL = releaseTarball(base, rel, name)
		cand.Available = true
		cand.Verified = digest != ""
		if !cand.Verified {
			cand.Note = "internal release has no sha256 pinned"
		}
		return cand, nil
	}
	cand.Available = false
	cand.Verified = false
	cand.Note = fmt.Sprintf("internal registry has no published release for %s@%s", name, version)
	return cand, nil
}

// HTTPResolver queries a running protected registry's /v1/release endpoint and
// returns a candidate whose digest comes from the server over net/http.
type HTTPResolver struct {
	BaseURL string
	Client  *http.Client
}

// InternalCandidate implements CandidateResolver.
func (r HTTPResolver) InternalCandidate(ctx context.Context, name, version string) (*SourceCandidate, error) {
	client := r.Client
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	q := url.Values{}
	q.Set("name", name)
	if version != "" {
		q.Set("version", version)
	}
	endpoint := stringsTrimSlash(r.BaseURL) + "/v1/release?" + q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return &SourceCandidate{
			Kind:      RegistryInternal,
			SourceURL: internalTarballURL(r.BaseURL, name, version),
			Version:   version,
			Available: false,
			Note:      "protected registry reports 404 (no public fallback); publish the reserved name",
		}, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("registry release lookup %s: status %d", endpoint, resp.StatusCode)
	}
	var rel InternalRelease
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return nil, fmt.Errorf("decode release: %w", err)
	}
	digest, _ := NormalizeSHA256(rel.SHA256)
	tarball := rel.Tarball
	if tarball == "" {
		tarball = internalTarballURL(r.BaseURL, name, rel.Version)
	}
	return &SourceCandidate{
		Kind:      RegistryInternal,
		SourceURL: tarball,
		Version:   rel.Version,
		SHA256:    digest,
		Available: true,
		Verified:  digest != "",
	}, nil
}

func stringsTrimSlash(s string) string {
	for len(s) > 0 && (s[len(s)-1] == '/' || s[len(s)-1] == ' ') {
		s = s[:len(s)-1]
	}
	return s
}
