package namespace

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func newHTTPTestServer(t *testing.T, now time.Time) (*httptest.Server, *Service, *Store) {
	t.Helper()
	service, store, _ := testService(t, now)
	server := httptest.NewServer(NewHandler(service))
	t.Cleanup(server.Close)
	return server, service, store
}

func requestJSON(t *testing.T, server *httptest.Server, method, path, token string, body any) (*http.Response, []byte) {
	t.Helper()
	var reader io.Reader
	if body != nil {
		payload, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal request: %v", err)
		}
		reader = bytes.NewReader(payload)
	}
	req, err := http.NewRequest(method, server.URL+path, reader)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("X-Request-ID", "http-test-request")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	payload, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	return resp, payload
}

func decodeResponse[T any](t *testing.T, payload []byte) T {
	t.Helper()
	var value T
	if err := json.Unmarshal(payload, &value); err != nil {
		t.Fatalf("decode response %s: %v", string(payload), err)
	}
	return value
}

func errorCode(t *testing.T, payload []byte) string {
	t.Helper()
	var response struct {
		Error Error `json:"error"`
	}
	if err := json.Unmarshal(payload, &response); err != nil {
		t.Fatalf("decode error response %s: %v", string(payload), err)
	}
	return response.Error.Code
}

func TestHTTPOwnershipWorkflow(t *testing.T) {
	now := time.Date(2026, 11, 26, 2, 0, 0, 0, time.UTC)
	server, _, _ := newHTTPTestServer(t, now)

	resp, payload := requestJSON(t, server, http.MethodGet, "/api/v1/namespaces", "", nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthorized status = %d: %s", resp.StatusCode, payload)
	}
	if code := errorCode(t, payload); code != "unauthorized" {
		t.Fatalf("unauthorized code = %s", code)
	}

	resp, payload = requestJSON(t, server, http.MethodPost, "/api/v1/namespaces/claims", "bob-demo-token", map[string]any{
		"namespace": "legacy-tools",
		"reason":    "squat attempt",
	})
	if resp.StatusCode != http.StatusConflict || errorCode(t, payload) != "namespace_has_packages" {
		t.Fatalf("package namespace claim response = %d %s", resp.StatusCode, payload)
	}

	resp, payload = requestJSON(t, server, http.MethodPost, "/api/v1/namespaces", "bob-demo-token", map[string]any{
		"namespace": "legacy-tools",
		"reason":    "ordinary create attempt",
	})
	if resp.StatusCode != http.StatusConflict || errorCode(t, payload) != "namespace_has_packages" {
		t.Fatalf("ordinary package namespace create response = %d %s", resp.StatusCode, payload)
	}

	resp, payload = requestJSON(t, server, http.MethodPost, "/api/v1/claims", "bob-demo-token", map[string]any{
		"namespace": "new-team",
		"reason":    "new team needs ownership",
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create claim response = %d %s", resp.StatusCode, payload)
	}
	claim := decodeResponse[Claim](t, payload)
	if resp.Header.Get("X-Request-ID") != "http-test-request" {
		t.Fatalf("request id header = %q", resp.Header.Get("X-Request-ID"))
	}

	resp, payload = requestJSON(t, server, http.MethodPost, "/api/v1/admin/claims/"+claim.ID+"/approve", "bob-demo-token", map[string]any{})
	if resp.StatusCode != http.StatusForbidden || errorCode(t, payload) != "forbidden" {
		t.Fatalf("non-admin approval response = %d %s", resp.StatusCode, payload)
	}
	resp, payload = requestJSON(t, server, http.MethodPost, "/api/v1/admin/claims/"+claim.ID+"/approve", "admin-demo-token", map[string]any{
		"reservation_days": 30,
		"note":             "approved for internal team",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("approve response = %d %s", resp.StatusCode, payload)
	}

	resp, payload = requestJSON(t, server, http.MethodGet, "/api/v1/namespaces/new-team", "bob-demo-token", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("get namespace response = %d %s", resp.StatusCode, payload)
	}
	view := decodeResponse[NamespaceView](t, payload)
	if view.OwnerID != "bob" || !view.ReservationActive {
		t.Fatalf("namespace view = %+v", view)
	}

	resp, payload = requestJSON(t, server, http.MethodPost, "/api/v1/namespaces/new-team/transfer", "bob-demo-token", map[string]any{
		"to_user_id": "carol",
		"reason":     "handoff",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("transfer response = %d %s", resp.StatusCode, payload)
	}
	transferred := decodeResponse[NamespaceView](t, payload)
	if transferred.OwnerID != "carol" {
		t.Fatalf("transferred owner = %s", transferred.OwnerID)
	}
	resp, payload = requestJSON(t, server, http.MethodGet, "/api/v1/namespaces/new-team/history", "bob-demo-token", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("former owner history = %d %s", resp.StatusCode, payload)
	}

	resp, payload = requestJSON(t, server, http.MethodPost, "/api/v1/packages", "carol-demo-token", map[string]any{
		"namespace": "new-team",
		"name":      "service",
		"version":   "1.0.0",
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("publish response = %d %s", resp.StatusCode, payload)
	}

	resp, payload = requestJSON(t, server, http.MethodGet, "/api/v1/admin/audit?namespace=new-team", "admin-demo-token", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("audit response = %d %s", resp.StatusCode, payload)
	}
	var auditResponse struct {
		Items        []AuditEvent      `json:"items"`
		Verification AuditVerification `json:"verification"`
	}
	auditResponse = decodeResponse[struct {
		Items        []AuditEvent      `json:"items"`
		Verification AuditVerification `json:"verification"`
	}](t, payload)
	if !auditResponse.Verification.Valid || len(auditResponse.Items) < 4 {
		t.Fatalf("audit response = %+v", auditResponse)
	}
	foundTransfer := false
	for _, event := range auditResponse.Items {
		if event.Type == AuditOwnershipTransferred && event.FromOwnerID == "bob" && event.ToOwnerID == "carol" {
			foundTransfer = true
		}
	}
	if !foundTransfer {
		t.Fatal("transfer audit event not visible through HTTP")
	}

	resp, payload = requestJSON(t, server, http.MethodGet, "/api/v1/admin/audit", "bob-demo-token", nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("member audit response = %d %s", resp.StatusCode, payload)
	}
}

func TestHTTPAuditTarExport(t *testing.T) {
	now := time.Date(2026, 11, 26, 2, 0, 0, 0, time.UTC)
	server, service, _ := newHTTPTestServer(t, now)
	bob := login(t, service, "bob-demo-token")
	admin := login(t, service, "admin-demo-token")
	claim, err := service.CreateClaim(bob, CreateClaimRequest{Namespace: "export-team", Reason: "export test"}, RequestMeta{})
	if err != nil {
		t.Fatalf("create claim: %v", err)
	}
	if _, err := service.ApproveClaim(admin, claim.ID, ApproveClaimRequest{}, RequestMeta{}); err != nil {
		t.Fatalf("approve: %v", err)
	}
	resp, payload := requestJSON(t, server, http.MethodGet, "/api/v1/admin/audit/export", "admin-demo-token", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("export response = %d %s", resp.StatusCode, payload)
	}
	if contentType := resp.Header.Get("Content-Type"); !strings.Contains(contentType, "application/x-tar") {
		t.Fatalf("content type = %s", contentType)
	}
	if disposition := resp.Header.Get("Content-Disposition"); !strings.Contains(disposition, ".tar") {
		t.Fatalf("content disposition = %s", disposition)
	}
	files := readTar(t, payload)
	if _, ok := files["audit/manifest.json"]; !ok {
		t.Fatal("manifest missing from HTTP export")
	}
	if len(files) < 4 {
		t.Fatalf("expected manifest, readme, index and events, got %d entries", len(files))
	}
}
