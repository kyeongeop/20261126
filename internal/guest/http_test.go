package guest_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"guestshare/internal/guest"
)

func TestHTTPGuestInvitationFlow(t *testing.T) {
	root := copyFixture(t)
	current := time.Date(2026, 11, 26, 9, 0, 0, 0, time.UTC)
	service := newService(t, root, func() time.Time { return current })
	handler, err := guest.NewHandler(service, guest.HTTPConfig{
		AdminToken:  "test-admin-token",
		InviterName: "team",
	})
	if err != nil {
		t.Fatalf("create handler: %v", err)
	}
	server := httptest.NewServer(handler)
	defer server.Close()

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("create cookie jar: %v", err)
	}
	client := server.Client()
	client.Jar = jar

	var created struct {
		Invitation      guest.InvitationView `json:"invitation"`
		InvitationToken string               `json:"invitation_token"`
	}
	response := requestJSON(t, client, http.MethodPost, server.URL+"/api/invitations", map[string]any{
		"display_name": "External Reviewer",
		"directory":    "Design",
		"expires_at":   current.Add(time.Hour).Format(time.RFC3339),
	}, "test-admin-token", &created)
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("create status = %d", response.StatusCode)
	}
	if created.InvitationToken == "" {
		t.Fatalf("missing invitation credential: %+v", created)
	}

	response = requestJSON(t, client, http.MethodPost, server.URL+"/api/guest/join", map[string]any{
		"token": created.InvitationToken,
	}, "", nil)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("join status = %d", response.StatusCode)
	}
	if len(jar.Cookies(mustURL(t, server.URL))) == 0 {
		t.Fatal("join did not set a guest cookie")
	}

	var listing struct {
		AuthorizedDirectory string            `json:"authorized_directory"`
		Entries             []guest.EntryView `json:"entries"`
	}
	response = requestJSON(t, client, http.MethodGet, server.URL+"/api/guest/files", nil, "", &listing)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("list status = %d", response.StatusCode)
	}
	if listing.AuthorizedDirectory != "Design" {
		t.Fatalf("authorized directory = %q", listing.AuthorizedDirectory)
	}
	assertEntryNames(t, listing.Entries, "brief.txt", "notes")

	response = requestJSON(t, client, http.MethodGet, server.URL+"/api/guest/files/"+url.PathEscape("brief.txt"), nil, "", nil)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("download status = %d", response.StatusCode)
	}
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil || !bytes.Contains(body, []byte("Design team shared brief")) {
		t.Fatalf("unexpected download body: %q, err=%v", body, err)
	}

	response = requestJSON(t, client, http.MethodGet, server.URL+"/api/guest/files?path=../Finance", nil, "", nil)
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("traversal status = %d", response.StatusCode)
	}

	response = requestJSON(t, client, http.MethodGet, server.URL+"/api/invitations", nil, "", nil)
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated admin list status = %d", response.StatusCode)
	}
	response = requestJSON(t, client, http.MethodGet, server.URL+"/api/invitations", nil, "test-admin-token", nil)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("admin list status = %d", response.StatusCode)
	}

	response = requestJSON(t, client, http.MethodDelete,
		server.URL+"/api/invitations/"+created.Invitation.ID, nil, "test-admin-token", nil)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("revoke status = %d", response.StatusCode)
	}
	var apiError errorBodyForTest
	response = requestJSON(t, client, http.MethodGet, server.URL+"/api/guest/files", nil, "", &apiError)
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("revoked guest status = %d", response.StatusCode)
	}
	if apiError.Error.Code != "invitation_revoked" {
		t.Fatalf("revoked error code = %q", apiError.Error.Code)
	}
}

type errorBodyForTest struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func requestJSON(
	t *testing.T,
	client *http.Client,
	method, target string,
	body any,
	adminToken string,
	targetValue any,
) *http.Response {
	t.Helper()
	var reader io.Reader
	if body != nil {
		payload, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("encode request: %v", err)
		}
		reader = bytes.NewReader(payload)
	}
	request, err := http.NewRequest(method, target, reader)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if adminToken != "" {
		request.Header.Set("Authorization", "Bearer "+adminToken)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("send request: %v", err)
	}
	if targetValue != nil {
		defer response.Body.Close()
		if err := json.NewDecoder(response.Body).Decode(targetValue); err != nil {
			t.Fatalf("decode response: %v", err)
		}
	}
	return response
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse URL: %v", err)
	}
	return parsed
}
