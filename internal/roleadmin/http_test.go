package roleadmin

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newHTTPTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(NewHTTPHandler(testService(t)))
	t.Cleanup(server.Close)
	return server
}

func httpJSON(
	t *testing.T,
	client *http.Client,
	method string,
	url string,
	adminID string,
	body any,
) (*http.Response, []byte) {
	t.Helper()
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("json.Marshal() error = %v", err)
		}
		reader = bytes.NewReader(encoded)
	}
	request, err := http.NewRequest(method, url, reader)
	if err != nil {
		t.Fatalf("http.NewRequest() error = %v", err)
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if adminID != "" {
		request.Header.Set("X-Admin-ID", adminID)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("client.Do() error = %v", err)
	}
	responseBody, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("io.ReadAll() error = %v", err)
	}
	response.Body.Close()
	return response, responseBody
}

func TestHTTPPreviewAndPartialApprovalFlow(t *testing.T) {
	server := newHTTPTestServer(t)
	client := server.Client()

	response, body := httpJSON(
		t,
		client,
		http.MethodPost,
		server.URL+"/api/roles/billing_admin/diff",
		"alice",
		map[string]any{
			"base_version":    4,
			"parent_role_ids": []string{"security_auditor", "support_agent"},
		},
	)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("preview status = %d, body = %s", response.StatusCode, body)
	}
	var preview PreviewResult
	if err := json.Unmarshal(body, &preview); err != nil {
		t.Fatalf("decode preview: %v; body = %s", err, body)
	}
	if preview.Diff.Summary.InheritedAdded != 2 {
		t.Fatalf("preview inherited additions = %#v", preview.Diff.Inherited.Added)
	}

	response, body = httpJSON(
		t,
		client,
		http.MethodPost,
		server.URL+"/api/roles/billing_admin/change-requests",
		"alice",
		map[string]any{
			"base_version": 4,
			"direct_permissions": []string{
				"billing.invoice.read",
				"billing.invoice.write",
				"users.delete",
			},
		},
	)
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("submit status = %d, body = %s", response.StatusCode, body)
	}
	if strings.Contains(string(body), `"parents_removed":null`) {
		t.Fatalf("diff serialized an empty collection as null: %s", body)
	}
	var submitted ChangeRequest
	if err := json.Unmarshal(body, &submitted); err != nil {
		t.Fatalf("decode submitted request: %v", err)
	}
	if submitted.Status != ChangePending {
		t.Fatalf("submit status = %q, want pending_approval", submitted.Status)
	}
	if location := response.Header.Get("Location"); location != "/api/change-requests/"+submitted.ID {
		t.Fatalf("Location = %q", location)
	}

	response, body = httpJSON(
		t,
		client,
		http.MethodPost,
		server.URL+"/api/change-requests/"+submitted.ID+"/decision",
		"bob",
		map[string]any{
			"decision":         "approve",
			"approved_actions": []string{"billing.invoice.write"},
			"comment":          "invoice write only",
		},
	)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("approval status = %d, body = %s", response.StatusCode, body)
	}
	var approved ChangeRequest
	if err := json.Unmarshal(body, &approved); err != nil {
		t.Fatalf("decode approved request: %v", err)
	}
	if !approved.Approval.Partial {
		t.Fatal("HTTP partial approval was not marked partial")
	}

	response, body = httpJSON(t, client, http.MethodGet, server.URL+"/api/roles/billing_admin", "", nil)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("get role status = %d, body = %s", response.StatusCode, body)
	}
	var role Role
	if err := json.Unmarshal(body, &role); err != nil {
		t.Fatalf("decode role: %v", err)
	}
	if role.Version != 5 {
		t.Fatalf("role version = %d, want 5", role.Version)
	}
	if !contains(role.DirectPermissions, "billing.invoice.write") {
		t.Fatalf("approved permission missing: %#v", role.DirectPermissions)
	}
	if contains(role.DirectPermissions, "users.delete") {
		t.Fatalf("unapproved permission present: %#v", role.DirectPermissions)
	}
}

func TestHTTPReturnsStructuredErrors(t *testing.T) {
	server := newHTTPTestServer(t)
	client := server.Client()

	response, body := httpJSON(
		t,
		client,
		http.MethodPost,
		server.URL+"/api/roles/billing_admin/diff",
		"",
		map[string]any{"base_version": 4},
	)
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body = %s", response.StatusCode, body)
	}
	assertErrorCode(t, body, "admin_required")

	request, err := http.NewRequest(
		http.MethodPost,
		server.URL+"/api/roles/billing_admin/diff",
		strings.NewReader(`{"base_version":4,"unexpected":true}`),
	)
	if err != nil {
		t.Fatalf("http.NewRequest() error = %v", err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Admin-ID", "alice")
	response, err = client.Do(request)
	if err != nil {
		t.Fatalf("client.Do() error = %v", err)
	}
	body, err = io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("io.ReadAll() error = %v", err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body = %s", response.StatusCode, body)
	}
	assertErrorCode(t, body, "invalid_json")
}

func assertErrorCode(t *testing.T, body []byte, want string) {
	t.Helper()
	var response struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		t.Fatalf("decode error response: %v; body = %s", err, body)
	}
	if response.Error.Code != want {
		t.Fatalf("error code = %q, want %q; body = %s", response.Error.Code, want, body)
	}
}
