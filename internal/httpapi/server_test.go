package httpapi

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"fileshare/internal/ratelimit"
	"fileshare/internal/shares"
	"fileshare/internal/store"
)

type harness struct {
	t         *testing.T
	server    *httptest.Server
	sharesMgr *shares.Manager
	ratePath  string
}

func newHarness(t *testing.T, cfg ratelimit.Config) *harness {
	t.Helper()
	dir := t.TempDir()
	sharesMgr, err := shares.NewManager(filepath.Join(dir, "shares.json"), 500)
	if err != nil {
		t.Fatal(err)
	}
	ratePath := filepath.Join(dir, "attempts.json")
	rateStore, err := store.Open[ratelimit.State](ratePath)
	if err != nil {
		t.Fatal(err)
	}
	svc := NewService(sharesMgr, rateStore, cfg, false, log.New(io.Discard, "", 0))
	server := httptest.NewServer(svc.NewMux())
	t.Cleanup(server.Close)
	return &harness{t: t, server: server, sharesMgr: sharesMgr, ratePath: ratePath}
}

func (h *harness) createShare(t *testing.T, filename, password string) string {
	t.Helper()
	body, _ := json.Marshal(createRequest{
		Filename: filename,
		Password: password,
		Content:  []byte("team file contents"),
	})
	resp, err := http.Post(h.server.URL+"/api/shares", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create status = %d", resp.StatusCode)
	}
	var created createResponse
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}
	return created.ShareID
}

func (h *harness) access(t *testing.T, shareID, password string) *http.Response {
	t.Helper()
	body, _ := json.Marshal(accessRequest{Password: password})
	resp, err := http.Post(
		h.server.URL+"/api/shares/"+shareID+"/access",
		"application/json",
		bytes.NewReader(body),
	)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func fastConfig() ratelimit.Config {
	return ratelimit.Config{
		MaxAttemptsPerWindow:   3,
		Window:                 time.Minute,
		MaxConsecutiveFailures: 3,
		Lockout:                200 * time.Millisecond,
	}
}

func TestSuccessfulAccessReturnsFile(t *testing.T) {
	h := newHarness(t, fastConfig())
	id := h.createShare(t, "doc.txt", "secret")

	resp := h.access(t, id, "secret")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var payload accessResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatal(err)
	}
	if payload.Filename != "doc.txt" || string(payload.Content) != "team file contents" {
		t.Fatalf("unexpected payload: %+v", payload)
	}
}

func TestFailuresLockThenRecover(t *testing.T) {
	h := newHarness(t, fastConfig())
	id := h.createShare(t, "doc.txt", "secret")

	// Three wrong attempts consume the quota; the next request is locked.
	for i := 0; i < 3; i++ {
		resp := h.access(t, id, "nope")
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("attempt %d status = %d, want 401", i+1, resp.StatusCode)
		}
		resp.Body.Close()
	}

	// Even the correct password is refused while the lock is active.
	resp := h.access(t, id, "secret")
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("locked status = %d, want 429", resp.StatusCode)
	}
	if resp.Header.Get("Retry-After") == "" {
		t.Fatal("locked response must carry Retry-After")
	}
	resp.Body.Close()

	// After the lockout elapses, the correct password works again.
	time.Sleep(250 * time.Millisecond)
	resp = h.access(t, id, "secret")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("recovered status = %d, want 200", resp.StatusCode)
	}
}

func TestUnknownShareAndWrongPasswordAreIndistinguishable(t *testing.T) {
	h := newHarness(t, fastConfig())
	id := h.createShare(t, "doc.txt", "secret")

	wrong := h.access(t, id, "bad-password")
	unknown := h.access(t, "nonexistent-share-id", "bad-password")
	defer wrong.Body.Close()
	defer unknown.Body.Close()

	if wrong.StatusCode != http.StatusUnauthorized || unknown.StatusCode != http.StatusUnauthorized {
		t.Fatalf("statuses differ: wrong=%d unknown=%d", wrong.StatusCode, unknown.StatusCode)
	}

	wrongBody, _ := io.ReadAll(wrong.Body)
	unknownBody, _ := io.ReadAll(unknown.Body)
	if !bytes.Equal(wrongBody, unknownBody) {
		t.Fatalf("response bodies differ and reveal share existence:\n%s\n%s", wrongBody, unknownBody)
	}
}

func TestLockPersistsAcrossRestart(t *testing.T) {
	cfg := fastConfig()
	cfg.Lockout = time.Hour // ensure the lock cannot naturally expire mid-test
	h := newHarness(t, cfg)
	id := h.createShare(t, "doc.txt", "secret")

	for i := 0; i < 3; i++ {
		resp := h.access(t, id, "nope")
		resp.Body.Close()
	}
	if resp := h.access(t, id, "nope"); resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("expected lock before restart, got %d", resp.StatusCode)
	} else {
		resp.Body.Close()
	}

	// Simulate a process restart: rebuild every in-memory component while
	// keeping the same files on disk.
	rateStore, err := store.Open[ratelimit.State](h.ratePath)
	if err != nil {
		t.Fatal(err)
	}
	restarted := NewService(h.sharesMgr, rateStore, cfg, false, log.New(io.Discard, "", 0))
	server := httptest.NewServer(restarted.NewMux())
	defer server.Close()

	body, _ := json.Marshal(accessRequest{Password: "secret"})
	resp, err := http.Post(server.URL+"/api/shares/"+id+"/access", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("lock did not survive restart: status = %d, want 429", resp.StatusCode)
	}
}

func TestLimitsArePerSource(t *testing.T) {
	dir := t.TempDir()
	sharesMgr, err := shares.NewManager(filepath.Join(dir, "shares.json"), 500)
	if err != nil {
		t.Fatal(err)
	}
	rateStore, err := store.Open[ratelimit.State](filepath.Join(dir, "attempts.json"))
	if err != nil {
		t.Fatal(err)
	}
	svc := NewService(sharesMgr, rateStore, fastConfig(), true, log.New(io.Discard, "", 0))
	server := httptest.NewServer(svc.NewMux())
	defer server.Close()
	h := &harness{t: t, server: server}
	id := h.createShare(t, "doc.txt", "secret")

	// Lock source A.
	for i := 0; i < 3; i++ {
		resp := h.accessWithXFF(t, id, "nope", "198.51.100.7")
		resp.Body.Close()
	}
	if resp := h.accessWithXFF(t, id, "nope", "198.51.100.7"); resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("expected lock, got %d", resp.StatusCode)
	} else {
		resp.Body.Close()
	}

	// Source B still has its full quota and can reach verification.
	resp := h.accessWithXFF(t, id, "nope", "198.51.100.8")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("source B should be independent, got status %d", resp.StatusCode)
	}
}

func (h *harness) accessWithXFF(t *testing.T, shareID, password, clientIP string) *http.Response {
	t.Helper()
	body, _ := json.Marshal(accessRequest{Password: password})
	req, err := http.NewRequest(http.MethodPost,
		h.server.URL+"/api/shares/"+shareID+"/access", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-For", clientIP)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}
