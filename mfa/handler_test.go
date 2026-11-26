package mfa

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func newHandlerServer() (*httptest.Server, *testEnv) {
	env := newTestEnv()
	return httptest.NewServer(NewHandler(env.service)), env
}

func doJSON(t *testing.T, method, url string, headers map[string]string, body any) (*http.Response, map[string]any) {
	t.Helper()
	var reader *bytes.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		reader = bytes.NewReader(raw)
	} else {
		reader = bytes.NewReader(nil)
	}
	req, err := http.NewRequest(method, url, reader)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	defer resp.Body.Close()
	var decoded map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return resp, decoded
}

func userHeaders(id string) map[string]string {
	return map[string]string{HeaderActorID: id, HeaderActorRole: string(RoleUser)}
}

func adminHeaders() map[string]string {
	return map[string]string{HeaderActorID: "u-admin", HeaderActorRole: string(RoleAdmin)}
}

func TestHTTPSubmitAndApproveFlow(t *testing.T) {
	server, env := newHandlerServer()
	defer server.Close()

	resp, body := doJSON(t, http.MethodPost, server.URL+"/mfa/reset-requests",
		userHeaders("u-alice"), map[string]any{
			"user_id":        "u-alice",
			"reason":         "phone stolen on commute",
			"window_minutes": 30,
			"notify_method":  "email",
			"end_condition":  "window_expiry",
		})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("submit status = %d body = %v", resp.StatusCode, body)
	}
	reqID, _ := body["id"].(string)
	if reqID == "" || body["status"] != "pending" {
		t.Fatalf("unexpected submit body: %v", body)
	}
	if _, leaked := body["recovery_token_hash"]; leaked {
		t.Fatal("response must not include the recovery token hash")
	}

	resp, body = doJSON(t, http.MethodPost,
		server.URL+"/mfa/reset-requests/"+reqID+"/approve",
		userHeaders("u-alice"), map[string]any{"note": "trying anyway"})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("non-admin approve status = %d", resp.StatusCode)
	}

	resp, body = doJSON(t, http.MethodPost,
		server.URL+"/mfa/reset-requests/"+reqID+"/approve",
		adminHeaders(), map[string]any{"note": "video verified"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("approve status = %d body = %v", resp.StatusCode, body)
	}
	if body["status"] != "active" {
		t.Fatalf("status = %v, want active", body["status"])
	}
	token, err := env.notifier.LastTokenFor("u-alice")
	if err != nil || token == "" {
		t.Fatalf("recovery token not delivered: %v", err)
	}

	resp, body = doJSON(t, http.MethodPost, server.URL+"/mfa/access-check",
		userHeaders("u-alice"), map[string]any{"user_id": "u-alice", "app_id": "app-high"})
	if resp.StatusCode != http.StatusForbidden || body["error"].(map[string]any)["code"] != "high_sensitive_blocked" {
		t.Fatalf("high-sensitive check = %d %v", resp.StatusCode, body)
	}

	resp, body = doJSON(t, http.MethodPost, server.URL+"/mfa/access-check",
		userHeaders("u-alice"), map[string]any{"user_id": "u-alice", "app_id": "app-low"})
	if resp.StatusCode != http.StatusOK || body["allowed"] != true {
		t.Fatalf("low-sensitivity check = %d %v", resp.StatusCode, body)
	}

	resp, body = doJSON(t, http.MethodPost,
		server.URL+"/mfa/reset-requests/"+reqID+"/reenroll",
		map[string]string{
			HeaderActorID: "u-alice", HeaderActorRole: string(RoleUser),
			HeaderRecoveryToken: token,
		}, nil)
	if resp.StatusCode != http.StatusOK || body["status"] != "reenrolled" {
		t.Fatalf("reenroll = %d %v", resp.StatusCode, body)
	}

	resp, body = doJSON(t, http.MethodPost, server.URL+"/mfa/access-check",
		userHeaders("u-alice"), map[string]any{"user_id": "u-alice", "app_id": "app-high"})
	if resp.StatusCode != http.StatusOK || body["allowed"] != true {
		t.Fatalf("access after reenroll = %d %v", resp.StatusCode, body)
	}
}

func TestHTTPRejectAndExpiryReEnrollment(t *testing.T) {
	server, env := newHandlerServer()
	defer server.Close()

	_, body := doJSON(t, http.MethodPost, server.URL+"/mfa/reset-requests",
		userHeaders("u-alice"), map[string]any{
			"user_id": "u-alice", "reason": "lost device", "window_minutes": 10,
			"notify_method": "email", "end_condition": "reenrollment",
		})
	reqID := body["id"].(string)

	resp, body := doJSON(t, http.MethodPost,
		server.URL+"/mfa/reset-requests/"+reqID+"/reject",
		adminHeaders(), map[string]any{"note": "identity not verifiable"})
	if resp.StatusCode != http.StatusOK || body["status"] != "rejected" {
		t.Fatalf("reject = %d %v", resp.StatusCode, body)
	}

	second, secondBody := doJSON(t, http.MethodPost, server.URL+"/mfa/reset-requests",
		userHeaders("u-alice"), map[string]any{
			"user_id": "u-alice", "reason": "second attempt", "window_minutes": 10,
			"notify_method": "email", "end_condition": "window_expiry",
		})
	if second.StatusCode != http.StatusCreated {
		t.Fatalf("second submit = %d %v", second.StatusCode, secondBody)
	}
	secondID := secondBody["id"].(string)
	approvedResp, _ := doJSON(t, http.MethodPost,
		server.URL+"/mfa/reset-requests/"+secondID+"/approve",
		adminHeaders(), map[string]any{"note": "ok"})
	if approvedResp.StatusCode != http.StatusOK {
		t.Fatalf("approve second request: %d", approvedResp.StatusCode)
	}

	env.clock.advance(11 * time.Minute)

	resp, body = doJSON(t, http.MethodPost, server.URL+"/mfa/access-check",
		userHeaders("u-alice"), map[string]any{"user_id": "u-alice", "app_id": "app-low"})
	if resp.StatusCode != http.StatusForbidden || body["error"].(map[string]any)["code"] != "mfa_required" {
		t.Fatalf("expired access = %d %v", resp.StatusCode, body)
	}

	resp, body = doJSON(t, http.MethodPost, server.URL+"/mfa/enroll",
		userHeaders("u-alice"), map[string]any{"user_id": "u-alice", "secret": "fresh-secret"})
	if resp.StatusCode != http.StatusOK || body["mfa_enrolled"] != true {
		t.Fatalf("enroll after expiry = %d %v", resp.StatusCode, body)
	}
	if _, leaked := body["mfa_secret"]; leaked {
		t.Fatal("user response must not include the MFA secret")
	}
}

func TestHTTPRejectsMissingActorAndBadPayload(t *testing.T) {
	server, _ := newHandlerServer()
	defer server.Close()

	req, _ := http.NewRequest(http.MethodGet, server.URL+"/mfa/reset-requests", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("missing actor status = %d, want 401", resp.StatusCode)
	}

	req, _ = http.NewRequest(http.MethodPost, server.URL+"/mfa/reset-requests",
		strings.NewReader(`{"user_id":"u-alice",`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(HeaderActorID, "u-alice")
	req.Header.Set(HeaderActorRole, string(RoleUser))
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("malformed JSON status = %d, want 400", resp.StatusCode)
	}
}
