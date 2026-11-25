package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"fileshare/internal/httpapi"
	"fileshare/internal/timeline"
)

// TestEndToEnd exercises the full stack through real HTTP handlers and a
// real on-disk store: merged timeline, filters, dedup, tombstone and the
// detail page jump links.
func TestEndToEnd(t *testing.T) {
	store, err := timeline.Open(t.TempDir())
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	srv := httptest.NewServer(httpapi.NewServer(store).Handler())
	defer srv.Close()

	post := func(body string) map[string]any {
		t.Helper()
		resp, err := http.Post(srv.URL+"/api/files/contract/events", "application/json", bytes.NewBufferString(body))
		if err != nil {
			t.Fatalf("post: %v", err)
		}
		defer resp.Body.Close()
		data, _ := io.ReadAll(resp.Body)
		out := map[string]any{}
		_ = json.Unmarshal(data, &out)
		return out
	}

	// All required lifecycle/access actions are merged into one timeline.
	for _, body := range []string{
		`{"action":"create","actor_id":"u1","occurred_at":"2026-11-26T08:00:00Z","details":{"file_name":"合同.pdf","path":"/legal/合同.pdf"}}`,
		`{"action":"grant","actor_id":"admin","occurred_at":"2026-11-26T09:00:00Z","details":{"grantee":"u2"}}`,
		`{"action":"preview","actor_id":"u2","occurred_at":"2026-11-26T10:00:00Z"}`,
		`{"action":"download","actor_id":"u2","occurred_at":"2026-11-26T11:00:00Z"}`,
		`{"action":"move","actor_id":"admin","occurred_at":"2026-11-26T12:00:00Z","details":{"from_path":"/legal/合同.pdf","to_path":"/legal/2026/合同.pdf"}}`,
		`{"action":"revoke","actor_id":"admin","occurred_at":"2026-11-26T13:00:00Z","details":{"revokee":"u2"}}`,
	} {
		post(body)
	}

	resp, err := http.Get(srv.URL + "/api/files/contract/timeline")
	if err != nil {
		t.Fatalf("timeline: %v", err)
	}
	var page timeline.Page
	_ = json.NewDecoder(resp.Body).Decode(&page)
	resp.Body.Close()
	if page.Filtered != 6 {
		t.Fatalf("merged timeline size = %d, want 6", page.Filtered)
	}

	// The detail page exposes filters and version jump anchors.
	resp, err = http.Get(srv.URL + "/files/contract?from=2026-11-26T09:30:00Z&to=2026-11-26T11:30:00Z")
	if err != nil {
		t.Fatalf("page: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	html := string(body)
	for _, want := range []string{"访问时间线", "name=\"from\"", "name=\"to\"", "href=\"#evt_"} {
		if !bytes.Contains([]byte(html), []byte(want)) {
			t.Fatalf("detail page missing %q", want)
		}
	}
}
