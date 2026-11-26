package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func newTestRegistry(t *testing.T, guard *Guard) (*Store, *httptest.Server) {
	t.Helper()
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	srv := NewServer(store, guard)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return store, ts
}

func publishTar(t *testing.T, ts *httptest.Server, name, version string, tar []byte) (Release, int) {
	t.Helper()
	q := url.Values{}
	q.Set("name", name)
	q.Set("version", version)
	req, err := http.NewRequest(http.MethodPut, ts.URL+"/v1/publish?"+q.Encode(), bytes.NewReader(tar))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var rel Release
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusCreated {
		if err := json.Unmarshal(body, &rel); err != nil {
			t.Fatalf("decode release: %v body=%s", err, body)
		}
	}
	return rel, resp.StatusCode
}

func TestRegistryPublishDigestDownloadAndImmutable(t *testing.T) {
	guard := &Guard{Classifier: NewClassifier(NamespacePolicy{Prefixes: []string{"@acme/"}})}
	_, ts := newTestRegistry(t, guard)

	tar, err := BuildTar(map[string]string{"package/index.js": "module.exports=1"})
	if err != nil {
		t.Fatal(err)
	}
	digest := DigestBytes(tar)

	rel, status := publishTar(t, ts, "@acme/core", "1.4.0", tar)
	if status != http.StatusCreated {
		t.Fatalf("publish status = %d", status)
	}
	if rel.SHA256 != digest {
		t.Fatalf("release digest %s != artifact digest %s", rel.SHA256, digest)
	}

	// Duplicate name@version is rejected.
	_, dupStatus := publishTar(t, ts, "@acme/core", "1.4.0", tar)
	if dupStatus != http.StatusConflict {
		t.Fatalf("republish status = %d, want 409", dupStatus)
	}

	// Tarball bytes and Digest header must match.
	q := url.Values{}
	q.Set("name", "@acme/core")
	q.Set("version", "1.4.0")
	resp, err := http.Get(ts.URL + "/v1/tarball?" + q.Encode())
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("tarball status %d", resp.StatusCode)
	}
	got, _ := io.ReadAll(resp.Body)
	if !bytes.Equal(got, tar) {
		t.Fatal("downloaded tar bytes do not match published artifact")
	}
	if resp.Header.Get("Digest") != digest {
		t.Fatalf("Digest header %q != %q", resp.Header.Get("Digest"), digest)
	}
}

func TestReservedNameNeverFallsBackToPublic(t *testing.T) {
	var upstreamCalls int
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls++
		w.WriteHeader(http.StatusNotFound)
	}))
	defer upstream.Close()

	catalog := &PublicCatalog{Packages: map[string]PublicPackage{
		"@acme/squat": {Name: "@acme/squat", Latest: "9.9.9"},
	}}
	guard := &Guard{
		Classifier:          NewClassifier(NamespacePolicy{Prefixes: []string{"@acme/"}, Exact: []string{"acme-billing"}}),
		Public:              catalog,
		AllowPublicFallback: true, // even when enabled globally...
	}
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	srv := NewServer(store, guard)
	srv.UpstreamBase = upstream.URL
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	get := func(path string) (int, map[string]any, http.Header) {
		resp, err := http.Get(ts.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var body map[string]any
		b, _ := io.ReadAll(resp.Body)
		_ = json.Unmarshal(b, &body)
		return resp.StatusCode, body, resp.Header
	}

	q := url.Values{}
	q.Set("name", "@acme/squat")

	status, body, headers := get("/v1/release?" + q.Encode())
	if status != http.StatusNotFound {
		t.Fatalf("reserved missing release status = %d want 404", status)
	}
	if headers.Get("X-Depguard-Protection") != "reserved-no-public-fallback" {
		t.Fatalf("missing protection header, got %q", headers.Get("X-Depguard-Protection"))
	}
	prot, _ := body["dependency_confusion_protection"].(map[string]any)
	if prot == nil || prot["blocked"] != true || prot["public_fallback_performed"] != false {
		t.Fatalf("bad protection body: %+v", body)
	}
	if prot["public_catalog_has_same_name"] != true {
		t.Fatalf("expected public collision evidence: %+v", prot)
	}
	if upstreamCalls != 0 {
		t.Fatalf("reserved name must not contact public upstream, calls=%d", upstreamCalls)
	}

	status, _, _ = get("/v1/tarball?" + q.Encode())
	if status != http.StatusNotFound || upstreamCalls != 0 {
		t.Fatalf("reserved tarball must 404 without upstream, status=%d calls=%d", status, upstreamCalls)
	}

	// An unreserved package is allowed to use the explicit upstream hook,
	// proving the block is namespace-specific rather than a dead proxy.
	_, _, _ = get("/v1/release?name=lodash")
	if upstreamCalls != 1 {
		t.Fatalf("unreserved fallback should proxy once, calls=%d", upstreamCalls)
	}
}

func TestHTTPResolverReturnsVerifiedCandidate(t *testing.T) {
	guard := &Guard{Classifier: NewClassifier(NamespacePolicy{Prefixes: []string{"@acme/"}})}
	_, ts := newTestRegistry(t, guard)
	tar, _ := BuildTar(map[string]string{"package/index.js": "x"})
	digest := DigestBytes(tar)
	_, status := publishTar(t, ts, "@acme/core", "1.4.0", tar)
	if status != http.StatusCreated {
		t.Fatalf("publish failed: %d", status)
	}

	res := HTTPResolver{BaseURL: ts.URL}
	cand, err := res.InternalCandidate(context.Background(), "@acme/core", "1.4.0")
	if err != nil {
		t.Fatal(err)
	}
	if !cand.Available || !cand.Verified || cand.SHA256 != digest {
		t.Fatalf("candidate not verified: %+v", cand)
	}
	if cand.SourceURL == "" || !contains(cand.SourceURL, "/v1/tarball") {
		t.Fatalf("bad candidate url: %s", cand.SourceURL)
	}

	missing, err := res.InternalCandidate(context.Background(), "@acme/nope", "9.9.9")
	if err != nil {
		t.Fatal(err)
	}
	if missing.Available {
		t.Fatal("missing internal package candidate must be unavailable, not a public source")
	}
}

func contains(s, sub string) bool {
	return bytes.Contains([]byte(s), []byte(sub))
}

func TestCheckerUsesHTTPResolverCandidate(t *testing.T) {
	guard := &Guard{Classifier: NewClassifier(NamespacePolicy{Prefixes: []string{"@acme/"}, Fallback: "deny"})}
	_, ts := newTestRegistry(t, guard)
	tar, _ := BuildTar(map[string]string{"package/index.js": "module.exports={}"})
	digest := DigestBytes(tar)
	if _, status := publishTar(t, ts, "@acme/core", "1.4.0", tar); status != http.StatusCreated {
		t.Fatalf("publish status %d", status)
	}

	cfg := &Config{
		Registries: []Registry{
			{ID: "internal", URL: ts.URL, Kind: RegistryInternal},
			{ID: "public", URL: "https://registry.npmjs.org", Kind: RegistryPublic, Default: true},
		},
		Namespace: NamespacePolicy{InternalRegistryID: "internal", Prefixes: []string{"@acme/"}, Fallback: "deny"},
	}
	mf := &Manifest{Dependencies: []Dependency{{Name: "@acme/core", Spec: "1.4.0"}}}
	lf := &Lockfile{Entries: []LockEntry{{
		Name:     "@acme/core",
		Version:  "1.4.0",
		Resolved: "https://registry.npmjs.org/@acme/core/-/core-1.4.0.tgz",
	}}}

	checker := NewChecker(cfg, mf, lf, nil, nil, WithResolver(HTTPResolver{BaseURL: ts.URL}))
	report, err := checker.Check(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	findings := ruleFindings(report, RuleLockfileOverride, "@acme/core")
	if len(findings) == 0 {
		t.Fatal("expected DG104 for public resolution of internal package")
	}
	var verified bool
	for _, f := range findings {
		if f.Candidate != nil && f.Candidate.Verified && f.Candidate.SHA256 == digest {
			verified = true
		}
	}
	if !verified {
		t.Fatalf("expected an HTTP-verified internal candidate with digest %s: %+v", digest, findings)
	}
}
