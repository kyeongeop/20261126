package server_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"previewtoken/server"
	"previewtoken/token"
)

type testEnv struct {
	mgr *token.Manager
	srv *httptest.Server
	now *time.Time
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	now := time.Date(2026, 11, 26, 10, 0, 0, 0, time.UTC)
	secret := []byte("http-test-secret-0123456789abcd")
	store := token.NewJSONStore(filepath.Join(t.TempDir(), "tokens.json"))
	mgr, err := token.NewManager(secret, store,
		token.WithClock(func() time.Time { return now }),
		token.WithDefaultTTL(5*time.Minute),
	)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	s := server.New(mgr)
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	return &testEnv{mgr: mgr, srv: ts, now: &now}
}

func (e *testEnv) post(t *testing.T, path string, body any) (int, map[string]any) {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	res, err := http.Post(e.srv.URL+path, "application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	defer res.Body.Close()
	data, _ := io.ReadAll(res.Body)
	out := map[string]any{}
	_ = json.Unmarshal(data, &out)
	return res.StatusCode, out
}

func (e *testEnv) get(t *testing.T, path string) *http.Response {
	t.Helper()
	res, err := http.Get(e.srv.URL + path)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	return res
}

func TestHealth(t *testing.T) {
	env := newTestEnv(t)
	res := env.get(t, "/healthz")
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("health status = %d", res.StatusCode)
	}
}

func TestIssuePreviewThenReplayHTTP(t *testing.T) {
	env := newTestEnv(t)

	status, issued := env.post(t, "/api/preview/tokens", map[string]any{
		"file": "plans/q4.pdf", "version": "v7", "user": "alice",
		"purpose": "preview", "ttl_seconds": 120,
	})
	if status != http.StatusCreated {
		t.Fatalf("issue status = %d body=%v", status, issued)
	}
	tok, _ := issued["token"].(string)
	if tok == "" {
		t.Fatal("missing token in response")
	}
	url, _ := issued["preview_url"].(string)
	if url == "" {
		t.Fatal("missing preview_url")
	}

	first := env.get(t, url+"&user=alice")
	body, _ := io.ReadAll(first.Body)
	first.Body.Close()
	if first.StatusCode != http.StatusOK {
		t.Fatalf("first preview status = %d body=%s", first.StatusCode, body)
	}
	if cc := first.Header.Get("Cache-Control"); cc == "" {
		t.Fatal("expected Cache-Control header on one-time preview")
	}

	second := env.get(t, url+"&user=alice")
	defer second.Body.Close()
	if second.StatusCode != http.StatusUnauthorized {
		t.Fatalf("replay status = %d, want 401", second.StatusCode)
	}
	var errBody map[string]any
	_ = json.NewDecoder(second.Body).Decode(&errBody)
	if errBody["reason"] != "replayed" {
		t.Fatalf("replay reason = %v, want replayed", errBody["reason"])
	}
}

func TestVerifyEndpointClassifiesFailures(t *testing.T) {
	env := newTestEnv(t)

	_, issued := env.post(t, "/api/preview/tokens", map[string]any{
		"file": "f", "version": "1", "user": "u", "purpose": "preview",
	})
	tok, _ := issued["token"].(string)

	// Wrong user -> 403 binding_mismatch.
	status, body := env.post(t, "/api/preview/verify", map[string]any{
		"token": tok, "file": "f", "version": "1", "user": "mallory",
	})
	if status != http.StatusForbidden || body["reason"] != "binding_mismatch" {
		t.Fatalf("mismatch = %d %v", status, body)
	}

	// Correct verification consumes the token.
	status, body = env.post(t, "/api/preview/verify", map[string]any{
		"token": tok, "file": "f", "version": "1", "user": "u",
	})
	if status != http.StatusOK || body["valid"] != true {
		t.Fatalf("verify = %d %v", status, body)
	}

	// Replay -> 401 replayed.
	status, body = env.post(t, "/api/preview/verify", map[string]any{"token": tok})
	if status != http.StatusUnauthorized || body["reason"] != "replayed" {
		t.Fatalf("replay verify = %d %v", status, body)
	}

	// Garbage token -> 401 invalid_token.
	status, body = env.post(t, "/api/preview/verify", map[string]any{"token": "garbage"})
	if status != http.StatusUnauthorized || body["reason"] != "invalid_token" {
		t.Fatalf("invalid verify = %d %v", status, body)
	}
}

func TestExpiredTokenHTTP(t *testing.T) {
	env := newTestEnv(t)
	_, issued := env.post(t, "/api/preview/tokens", map[string]any{
		"file": "f", "version": "1", "user": "u", "ttl_seconds": 30,
	})
	tok, _ := issued["token"].(string)

	*env.now = env.now.Add(31 * time.Second)
	status, body := env.post(t, "/api/preview/verify", map[string]any{"token": tok})
	if status != http.StatusUnauthorized || body["reason"] != "expired" {
		t.Fatalf("expired = %d %v", status, body)
	}
}

func TestPathStylePreviewBinding(t *testing.T) {
	env := newTestEnv(t)
	_, issued := env.post(t, "/api/preview/tokens", map[string]any{
		"file": "specs/api.md", "version": "v2", "user": "bob",
	})
	tok, _ := issued["token"].(string)

	// Path asserts file/version; matching request succeeds.
	res := env.get(t, "/files/specs/api.md/versions/v2/preview?token="+tok+"&user=bob")
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("path preview = %d body=%s", res.StatusCode, body)
	}
}

func TestDemoPageServed(t *testing.T) {
	env := newTestEnv(t)
	for _, path := range []string{"/", "/demo"} {
		res := env.get(t, path)
		data, _ := io.ReadAll(res.Body)
		res.Body.Close()
		if res.StatusCode != http.StatusOK || !bytes.Contains(data, []byte("缩略图")) {
			t.Fatalf("demo %s status=%d contains-title=%v", path, res.StatusCode,
				bytes.Contains(data, []byte("缩略图")))
		}
	}
}

func TestValidateDoesNotConsume(t *testing.T) {
	env := newTestEnv(t)
	_, issued := env.post(t, "/api/preview/tokens", map[string]any{
		"file": "f", "version": "1", "user": "u",
	})
	tok, _ := issued["token"].(string)

	for i := 0; i < 2; i++ {
		status, body := env.post(t, "/api/preview/validate", map[string]any{"token": tok})
		if status != http.StatusOK || body["valid"] != true {
			t.Fatalf("validate #%d = %d %v", i, status, body)
		}
	}

	// The token is still spendable after repeated validate calls.
	status, _ := env.post(t, "/api/preview/verify", map[string]any{"token": tok})
	if status != http.StatusOK {
		t.Fatalf("verify after validate = %d, want 200", status)
	}
	status, body := env.post(t, "/api/preview/validate", map[string]any{"token": tok})
	if status != http.StatusUnauthorized || body["reason"] != "replayed" {
		t.Fatalf("validate after consume = %d %v", status, body)
	}
}

func TestCommonAliases(t *testing.T) {
	env := newTestEnv(t)

	if res := env.get(t, "/ping"); res.StatusCode != http.StatusOK {
		t.Fatalf("/ping status=%d", res.StatusCode)
	} else {
		res.Body.Close()
	}

	status, issued := env.post(t, "/api/preview/issue", map[string]any{
		"filename": "alias.txt", "version": "v1", "user_id": "u9",
	})
	if status != http.StatusCreated {
		t.Fatalf("alias issue status=%d body=%v", status, issued)
	}
	if _, ok := issued["access_token"].(string); !ok {
		t.Fatal("expected access_token alias in response")
	}
}

func TestTokenInPathAlias(t *testing.T) {
	env := newTestEnv(t)
	_, issued := env.post(t, "/api/preview/tokens", map[string]any{
		"file": "f", "version": "1", "user": "u",
	})
	tok, _ := issued["token"].(string)

	res := env.get(t, "/preview/"+tok)
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("path token status=%d body=%s", res.StatusCode, body)
	}

	// The alias consumes the same one-time token.
	res = env.get(t, "/preview/"+tok)
	res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("path token replay status=%d want 401", res.StatusCode)
	}
}
