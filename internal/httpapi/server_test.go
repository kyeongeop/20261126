package httpapi

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"fileshare/internal/timeline"
)

func newTestServer(t *testing.T) (*httptest.Server, *timeline.Store) {
	t.Helper()
	store, err := timeline.Open(t.TempDir())
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	srv := httptest.NewServer(NewServer(store).Handler())
	t.Cleanup(srv.Close)
	return srv, store
}

func postJSON(t *testing.T, url string, body string) (int, map[string]any) {
	t.Helper()
	resp, err := http.Post(url, "application/json", bytes.NewBufferString(body))
	if err != nil {
		t.Fatalf("post %s: %v", url, err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	out := map[string]any{}
	if len(data) > 0 {
		_ = json.Unmarshal(data, &out)
	}
	return resp.StatusCode, out
}

func seedTimeline(t *testing.T, baseURL string) {
	t.Helper()
	events := []string{
		`{"action":"create","actor_id":"u1","occurred_at":"2026-11-26T08:00:00Z","version_id":"v1","details":{"file_name":"季度预算.xlsx","path":"/finance/预算.xlsx"}}`,
		`{"action":"grant","actor_id":"admin","occurred_at":"2026-11-26T09:00:00Z","details":{"grantee":"u2","role":"viewer"}}`,
		`{"action":"preview","actor_id":"u2","occurred_at":"2026-11-26T10:00:00Z","details":{"ip":"10.0.0.8"}}`,
		`{"action":"download","actor_id":"u2","occurred_at":"2026-11-26T11:00:00Z","version_id":"v2"}`,
		`{"action":"move","actor_id":"admin","occurred_at":"2026-11-26T12:00:00Z","version_id":"v2","details":{"from_path":"/finance/预算.xlsx","to_path":"/archive/预算.xlsx"}}`,
		`{"action":"revoke","actor_id":"admin","occurred_at":"2026-11-26T13:00:00Z","version_id":"v2","details":{"revokee":"u2"}}`,
	}
	for _, body := range events {
		status, out := postJSON(t, baseURL+"/api/files/fin-budget/events", body)
		if status != http.StatusCreated {
			t.Fatalf("seed status = %d body=%v", status, out)
		}
	}
}

func TestIngestAndTimelineAPI(t *testing.T) {
	srv, _ := newTestServer(t)
	seedTimeline(t, srv.URL)

	resp, err := http.Get(srv.URL + "/api/files/fin-budget/timeline")
	if err != nil {
		t.Fatalf("get timeline: %v", err)
	}
	defer resp.Body.Close()
	var page timeline.Page
	if err := json.NewDecoder(resp.Body).Decode(&page); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if page.Total != 6 || page.Filtered != 6 {
		t.Fatalf("counts = %+v, want 6/6", page)
	}
	if page.Events[0].Action != timeline.ActionCreate {
		t.Fatalf("first event = %s, want create", page.Events[0].Action)
	}

	// Filters: user + action + time window.
	resp, err = http.Get(srv.URL +
		"/api/files/fin-budget/timeline?user=u2&action=download&from=2026-11-26T10:30:00Z&to=2026-11-26T11:30:00Z")
	if err != nil {
		t.Fatalf("filtered get: %v", err)
	}
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(&page); err != nil {
		t.Fatalf("decode filtered: %v", err)
	}
	if page.Filtered != 1 || page.Events[0].ActorID != "u2" {
		t.Fatalf("filtered page = %+v", page)
	}

	// Version filter for the jump-to-version feature.
	resp, err = http.Get(srv.URL + "/api/files/fin-budget/timeline?version=v2")
	if err != nil {
		t.Fatalf("version get: %v", err)
	}
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(&page); err != nil {
		t.Fatalf("decode version: %v", err)
	}
	if page.Filtered != 3 {
		t.Fatalf("v2 events = %d, want 3", page.Filtered)
	}
}

func TestIdempotentReportingAndDelete(t *testing.T) {
	srv, _ := newTestServer(t)
	body := `{"action":"preview","actor_id":"u2","occurred_at":"2026-11-26T10:00:00Z"}`
	status, first := postJSON(t, srv.URL+"/api/files/f1/events", body)
	if status != http.StatusCreated {
		t.Fatalf("first status = %d", status)
	}
	status, second := postJSON(t, srv.URL+"/api/files/f1/events", body)
	if status != http.StatusOK || second["duplicate"] != true {
		t.Fatalf("retry status=%d body=%v, want 200 duplicate", status, second)
	}

	eventMap := first["event"].(map[string]any)
	key := eventMap["dedup_key"].(string)
	req, _ := http.NewRequest(http.MethodDelete, srv.URL+"/api/events/"+key, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("delete status = %d", resp.StatusCode)
	}

	// GET marks tombstoned events as Gone.
	resp, err = http.Get(srv.URL + "/api/events/" + key)
	if err != nil {
		t.Fatalf("get deleted: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusGone {
		t.Fatalf("deleted event status = %d, want 410", resp.StatusCode)
	}

	// A duplicate report after deletion is suppressed, not re-created.
	status, suppressed := postJSON(t, srv.URL+"/api/files/f1/events", body)
	if status != http.StatusOK || suppressed["suppressed"] != true {
		t.Fatalf("post-delete report status=%d body=%v", status, suppressed)
	}

	// The timeline no longer contains the event.
	resp, err = http.Get(srv.URL + "/api/files/f1/timeline")
	if err != nil {
		t.Fatalf("timeline: %v", err)
	}
	defer resp.Body.Close()
	var page timeline.Page
	_ = json.NewDecoder(resp.Body).Decode(&page)
	if page.Total != 0 {
		t.Fatalf("live events after delete = %d, want 0", page.Total)
	}
}

func TestBatchIngest(t *testing.T) {
	srv, _ := newTestServer(t)
	body := `{"file_id":"f1","events":[
		{"action":"create","actor_id":"u1","occurred_at":"2026-11-26T08:00:00Z"},
		{"action":"preview","actor_id":"u1","occurred_at":"2026-11-26T09:00:00Z"},
		{"action":"bogus","actor_id":"u1"}
	]}`
	status, out := postJSON(t, srv.URL+"/api/events", body)
	if status != http.StatusCreated {
		t.Fatalf("batch status = %d body=%v", status, out)
	}
	if out["ingested"].(float64) != 2 {
		t.Fatalf("ingested = %v, want 2", out["ingested"])
	}
}

func TestValidationErrors(t *testing.T) {
	srv, _ := newTestServer(t)
	seedTimeline(t, srv.URL)

	status, _ := postJSON(t, srv.URL+"/api/files/f1/events",
		`{"action":"unknown","actor_id":"u1"}`)
	if status != http.StatusBadRequest {
		t.Fatalf("bad action status = %d, want 400", status)
	}
	status, _ = postJSON(t, srv.URL+"/api/files/f1/events", `{bad json`)
	if status != http.StatusBadRequest {
		t.Fatalf("bad json status = %d, want 400", status)
	}

	resp, err := http.Get(srv.URL + "/api/files/missing/timeline")
	if err != nil {
		t.Fatalf("missing file: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("missing file status = %d, want 404", resp.StatusCode)
	}

	resp, err = http.Get(srv.URL + "/api/files/fin-budget/timeline?action=not-an-action")
	if err != nil {
		t.Fatalf("bad filter: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad filter status = %d, want 400", resp.StatusCode)
	}
}

func TestDetailPageRenders(t *testing.T) {
	srv, _ := newTestServer(t)
	seedTimeline(t, srv.URL)

	resp, err := http.Get(srv.URL + "/files/fin-budget?user=u2&action=download")
	if err != nil {
		t.Fatalf("detail page: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("detail status = %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("content type = %q, want text/html", ct)
	}
	body, _ := io.ReadAll(resp.Body)
	html := string(body)
	for _, want := range []string{"访问时间线", "季度预算.xlsx", "下载", "name=\"user\"", "?version=v2"} {
		if !strings.Contains(html, want) {
			t.Fatalf("page missing %q", want)
		}
	}

	// Version jump highlights the version and lists only its events.
	resp2, err := http.Get(srv.URL + "/files/fin-budget?version=v1")
	if err != nil {
		t.Fatalf("version page: %v", err)
	}
	defer resp2.Body.Close()
	page2, _ := io.ReadAll(resp2.Body)
	if !strings.Contains(string(page2), "chip active") {
		t.Fatal("version chip should be marked active")
	}

	// Unknown file renders 404.
	resp3, err := http.Get(srv.URL + "/files/nope")
	if err != nil {
		t.Fatalf("missing page: %v", err)
	}
	resp3.Body.Close()
	if resp3.StatusCode != http.StatusNotFound {
		t.Fatalf("missing page status = %d, want 404", resp3.StatusCode)
	}
}

func TestIndexAndHealth(t *testing.T) {
	srv, _ := newTestServer(t)
	seedTimeline(t, srv.URL)

	resp, err := http.Get(srv.URL + "/healthz")
	if err != nil {
		t.Fatalf("health: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("health status = %d", resp.StatusCode)
	}

	resp, err = http.Get(srv.URL + "/")
	if err != nil {
		t.Fatalf("index: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "/files/fin-budget") {
		t.Fatal("index should link to the seeded file")
	}
}
