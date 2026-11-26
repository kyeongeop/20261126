package server

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

type harness struct {
	t      *testing.T
	server *Server
	share  string
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	share := filepath.Join(t.TempDir(), "share")
	state := filepath.Join(t.TempDir(), "state")
	srv, err := New(share, state)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(share, "team-a", "docs"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(share, "team-a", "docs", "report.txt"), []byte("secret"), 0o640); err != nil {
		t.Fatal(err)
	}
	return &harness{t: t, server: srv, share: share}
}

func (h *harness) do(method, target, role, id string, body any) (int, map[string]any) {
	h.t.Helper()
	var reader io.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		reader = bytes.NewReader(raw)
	}
	req := httptest.NewRequest(method, target, reader)
	req.Header.Set("X-Actor-Id", id)
	req.Header.Set("X-Actor-Role", role)
	rec := httptest.NewRecorder()
	h.server.Handler().ServeHTTP(rec, req)

	out := map[string]any{}
	if raw := rec.Body.Bytes(); len(raw) > 0 {
		if err := json.Unmarshal(raw, &out); err != nil {
			h.t.Fatalf("response not JSON (%d): %s", rec.Code, raw)
		}
	}
	return rec.Code, out
}

func TestIdentityRequired(t *testing.T) {
	h := newHarness(t)
	req := httptest.NewRequest(http.MethodGet, "/api/files/", nil)
	rec := httptest.NewRecorder()
	h.server.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestReadBeforeAndAfterFreeze(t *testing.T) {
	h := newHarness(t)

	code, body := h.do(http.MethodGet, "/api/files/team-a/docs", RoleUser, "u1", nil)
	if code != http.StatusOK {
		t.Fatalf("list before freeze: status %d body %v", code, body)
	}
	entries, _ := body["entries"].([]any)
	if len(entries) != 1 {
		t.Fatalf("entries = %v", entries)
	}

	// Non-admins cannot trigger the emergency freeze.
	code, body = h.do(http.MethodPost, "/api/admin/freeze", RoleUser, "u1",
		map[string]string{"path": "/team-a", "reason": "exfiltration"})
	if code != http.StatusForbidden {
		t.Fatalf("freeze by user: status %d, want 403", code)
	}

	// Freezing without a reason is rejected.
	code, _ = h.do(http.MethodPost, "/api/admin/freeze", RoleAdmin, "a1",
		map[string]string{"path": "/team-a"})
	if code != http.StatusBadRequest {
		t.Fatalf("freeze without reason: status %d, want 400", code)
	}

	code, body = h.do(http.MethodPost, "/api/admin/freeze", RoleAdmin, "a1",
		map[string]string{"path": "/team-a", "reason": "anomalous outbound transfer"})
	if code != http.StatusCreated {
		t.Fatalf("freeze: status %d body %v", code, body)
	}

	// Every role, including admin and background jobs, is denied afterwards.
	for _, role := range []string{RoleAdmin, RoleUser, RoleGuest, RoleBackground} {
		code, body = h.do(http.MethodGet, "/api/files/team-a/docs", role, "x", nil)
		if code != http.StatusForbidden || body["error"] != "directory_frozen" {
			t.Fatalf("list as %s: status %d body %v", role, code, body)
		}
		code, body = h.do(http.MethodGet, "/api/file?path=/team-a/docs/report.txt", role, "x", nil)
		if code != http.StatusForbidden || body["error"] != "directory_frozen" {
			t.Fatalf("read as %s: status %d body %v", role, code, body)
		}
	}

	// Untouched directories stay available.
	code, _ = h.do(http.MethodGet, "/api/files/", RoleUser, "u1", nil)
	if code != http.StatusOK {
		t.Fatalf("unrelated dir status = %d, want 200", code)
	}

	// The shared data itself must still exist on disk.
	if _, err := os.Stat(filepath.Join(h.share, "team-a", "docs", "report.txt")); err != nil {
		t.Fatalf("shared data deleted or moved: %v", err)
	}
}

func TestDeniedAccessIsRecorded(t *testing.T) {
	h := newHarness(t)
	if code, _ := h.do(http.MethodPost, "/api/admin/freeze", RoleAdmin, "a1",
		map[string]string{"path": "/team-a", "reason": "incident"}); code != http.StatusCreated {
		t.Fatalf("freeze status = %d", code)
	}
	h.do(http.MethodGet, "/api/files/team-a", RoleGuest, "g1", nil)
	h.do(http.MethodGet, "/api/file?path=/team-a/docs/report.txt", RoleBackground, "job-9", nil)

	code, body := h.do(http.MethodGet, "/api/admin/denied-access", RoleAdmin, "a1", nil)
	if code != http.StatusOK {
		t.Fatalf("denied-access status = %d", code)
	}
	events, _ := body["deniedAccess"].([]any)
	if len(events) != 2 {
		t.Fatalf("recorded events = %d, want 2", len(events))
	}
	first, _ := events[0].(map[string]any)
	if first["actorRole"] != RoleGuest || first["matchedFrozenPath"] != "/team-a" {
		t.Fatalf("unexpected first event: %v", first)
	}

	// Non-admins cannot read the incident logs.
	if code, _ := h.do(http.MethodGet, "/api/admin/denied-access", RoleUser, "u1", nil); code != http.StatusForbidden {
		t.Fatalf("guest log access status = %d, want 403", code)
	}
}

func TestUnfreezeRequiresReasonAndConfirmation(t *testing.T) {
	h := newHarness(t)
	h.do(http.MethodPost, "/api/admin/freeze", RoleAdmin, "a1",
		map[string]string{"path": "/team-a", "reason": "incident"})

	// Step 1: request with mandatory reason.
	code, body := h.do(http.MethodPost, "/api/admin/unfreeze-requests", RoleAdmin, "a1",
		map[string]string{"path": "/team-a", "reason": ""})
	if code != http.StatusBadRequest {
		t.Fatalf("request without reason: status %d, want 400", code)
	}
	code, body = h.do(http.MethodPost, "/api/admin/unfreeze-requests", RoleAdmin, "a1",
		map[string]string{"path": "/team-a", "reason": "forensics complete, no data loss"})
	if code != http.StatusCreated {
		t.Fatalf("unfreeze request: status %d body %v", code, body)
	}
	reqID, _ := body["id"].(string)

	// Still frozen between request and confirmation.
	if code, _ := h.do(http.MethodGet, "/api/files/team-a", RoleUser, "u1", nil); code != http.StatusForbidden {
		t.Fatalf("access while pending: status %d, want 403", code)
	}

	// Step 2: explicit administrator confirmation.
	code, body = h.do(http.MethodPost, "/api/admin/unfreeze-requests/"+reqID+"/confirm", RoleAdmin, "a2", nil)
	if code != http.StatusOK {
		t.Fatalf("confirm: status %d body %v", code, body)
	}

	code, _ = h.do(http.MethodGet, "/api/files/team-a/docs", RoleUser, "u1", nil)
	if code != http.StatusOK {
		t.Fatalf("list after unfreeze: status %d, want 200", code)
	}

	// Audit trail covers the whole lifecycle.
	_, auditBody := h.do(http.MethodGet, "/api/admin/audit", RoleAdmin, "a1", nil)
	entries, _ := auditBody["audit"].([]any)
	var actions []string
	for _, e := range entries {
		actions = append(actions, e.(map[string]any)["action"].(string))
	}
	want := []string{"freeze", "unfreeze-request", "unfreeze-confirm"}
	if len(actions) != 3 {
		t.Fatalf("audit actions = %v, want %v", actions, want)
	}
	for i := range want {
		if actions[i] != want[i] {
			t.Fatalf("audit actions = %v, want %v", actions, want)
		}
	}
}

func TestPathTraversalRejected(t *testing.T) {
	h := newHarness(t)
	code, _ := h.do(http.MethodGet, "/api/file?path=/../../etc/passwd", RoleUser, "u1", nil)
	if code != http.StatusBadRequest {
		t.Fatalf("traversal status = %d, want 400", code)
	}
}
