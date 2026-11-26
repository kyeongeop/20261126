package server

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"pkgregistry/internal/audit"
	"pkgregistry/internal/store"
	"pkgregistry/internal/token"
)

const adminToken = "test-admin-secret"

type fixture struct {
	t   *testing.T
	srv *httptest.Server
	dir string
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	dir := t.TempDir()
	tokens, err := token.OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	pkgs, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	auditLog, err := audit.Open(filepath.Join(dir, "audit.log"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { auditLog.Close() })
	s := New(tokens, pkgs, auditLog, adminToken)
	f := &fixture{t: t, srv: httptest.NewServer(s), dir: dir}
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fixture) do(method, path, token string, body io.Reader) *http.Response {
	f.t.Helper()
	req, err := http.NewRequest(method, f.srv.URL+path, body)
	if err != nil {
		f.t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		f.t.Fatal(err)
	}
	return resp
}

func (f *fixture) mintToken(t *testing.T, purpose, prefix, pattern string) string {
	t.Helper()
	reqBody, _ := json.Marshal(map[string]any{
		"label":            "test",
		"purpose":          purpose,
		"namespace_prefix": prefix,
		"package_pattern":  pattern,
	})
	resp := f.do(http.MethodPost, "/v1/admin/tokens", adminToken, bytes.NewReader(reqBody))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("mint token: status %d", resp.StatusCode)
	}
	var out struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	return out.Token
}

func makeTar(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	content := []byte("hello registry")
	if err := tw.WriteHeader(&tar.Header{Name: "pkg/main.go", Size: int64(len(content)), Mode: 0o644}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func (f *fixture) auditEvents(t *testing.T) []audit.Event {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(f.dir, "audit.log"))
	if err != nil {
		t.Fatal(err)
	}
	var events []audit.Event
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line == "" {
			continue
		}
		var e audit.Event
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatal(err)
		}
		events = append(events, e)
	}
	return events
}

func TestPublishFetchRevokeLifecycle(t *testing.T) {
	f := newFixture(t)
	pub := f.mintToken(t, "publish", "acme/", "")
	read := f.mintToken(t, "readonly", "acme/", "")
	rev := f.mintToken(t, "revoke", "acme/", "")
	path := "/v1/packages/acme/billing-api/1.0.0"

	// readonly token cannot publish.
	resp := f.do(http.MethodPut, path, read, bytes.NewReader(makeTar(t)))
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("readonly publish: got %d, want 404", resp.StatusCode)
	}

	// publish token publishes.
	resp = f.do(http.MethodPut, path, pub, bytes.NewReader(makeTar(t)))
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("publish: got %d, want 201", resp.StatusCode)
	}

	// publish token cannot read.
	resp = f.do(http.MethodGet, path, pub, nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("publish-token read: got %d, want 404", resp.StatusCode)
	}

	// readonly token reads.
	resp = f.do(http.MethodGet, path, read, nil)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("read: got %d, want 200", resp.StatusCode)
	}
	if !bytes.Equal(body, makeTar(t)) {
		t.Fatal("fetched archive differs from published one")
	}
	if resp.Header.Get("X-Content-SHA256") == "" {
		t.Fatal("missing sha256 header")
	}

	// readonly token cannot revoke; revoke token withdraws the version.
	resp = f.do(http.MethodPost, path+"/revoke", read, nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("readonly revoke: got %d, want 404", resp.StatusCode)
	}
	resp = f.do(http.MethodPost, path+"/revoke?reason=bad-build", rev, nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("revoke: got %d, want 200", resp.StatusCode)
	}

	// After revocation the package reads as gone.
	resp = f.do(http.MethodGet, path, read, nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("read after revoke: got %d, want 404", resp.StatusCode)
	}
}

// TestUniformErrors ensures failures never reveal whether another
// namespace prefix exists: out-of-scope, wrong-token and
// missing-package responses are byte-identical.
func TestUniformErrors(t *testing.T) {
	f := newFixture(t)
	acmeRead := f.mintToken(t, "readonly", "acme/", "")

	bodyOf := func(resp *http.Response) string {
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return string(b)
	}

	// 1. Valid token, out-of-scope namespace ("other/" may or may not exist).
	r1 := f.do(http.MethodGet, "/v1/packages/other/secret-pkg/9.9.9", acmeRead, nil)
	// 2. Valid token, in-scope namespace, package that does not exist.
	r2 := f.do(http.MethodGet, "/v1/packages/acme/nope/0.0.0", acmeRead, nil)
	// 3. No token at all.
	r3 := f.do(http.MethodGet, "/v1/packages/other/secret-pkg/9.9.9", "", nil)
	// 4. Garbage token.
	r4 := f.do(http.MethodGet, "/v1/packages/other/secret-pkg/9.9.9", "ireg_garbage", nil)

	b1, b2, b3, b4 := bodyOf(r1), bodyOf(r2), bodyOf(r3), bodyOf(r4)
	for i, resp := range []*http.Response{r1, r2, r3, r4} {
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("case %d: got %d, want 404", i+1, resp.StatusCode)
		}
	}
	if b1 != b2 || b2 != b3 || b3 != b4 {
		t.Fatalf("error bodies differ, leaking scope info: %q %q %q %q", b1, b2, b3, b4)
	}
}

// TestPackagePatternScope limits a token to matching package names.
func TestPackagePatternScope(t *testing.T) {
	f := newFixture(t)
	pub := f.mintToken(t, "publish", "acme/", "acme/billing-*")

	resp := f.do(http.MethodPut, "/v1/packages/acme/billing-api/1.0.0", pub, bytes.NewReader(makeTar(t)))
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("in-pattern publish: got %d, want 201", resp.StatusCode)
	}
	resp = f.do(http.MethodPut, "/v1/packages/acme/auth-api/1.0.0", pub, bytes.NewReader(makeTar(t)))
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("out-of-pattern publish: got %d, want 404", resp.StatusCode)
	}
}

// TestAuditCoverage checks that both successes and failures are logged.
func TestAuditCoverage(t *testing.T) {
	f := newFixture(t)
	read := f.mintToken(t, "readonly", "acme/", "")

	resp := f.do(http.MethodGet, "/v1/packages/acme/missing/1.0.0", read, nil)
	resp.Body.Close()
	resp = f.do(http.MethodGet, "/v1/packages/evil/x/1.0.0", "ireg_bad", nil)
	resp.Body.Close()

	var allow, deny int
	for _, e := range f.auditEvents(t) {
		switch e.Decision {
		case audit.Allow:
			allow++
		case audit.Deny:
			deny++
		}
	}
	if allow == 0 || deny < 2 {
		t.Fatalf("audit should record success and failure, got allow=%d deny=%d", allow, deny)
	}
	if err := audit.Verify(filepath.Join(f.dir, "audit.log")); err != nil {
		t.Fatalf("audit chain broken: %v", err)
	}
}

// TestAdminGate protects token administration.
func TestAdminGate(t *testing.T) {
	f := newFixture(t)
	body := strings.NewReader(`{"purpose":"readonly","namespace_prefix":"acme/"}`)

	resp := f.do(http.MethodPost, "/v1/admin/tokens", "", body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unauthenticated admin call: got %d, want 404", resp.StatusCode)
	}
	resp = f.do(http.MethodPost, "/v1/admin/tokens", "wrong-admin", strings.NewReader(`{}`))
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("wrong admin token: got %d, want 404", resp.StatusCode)
	}
}
