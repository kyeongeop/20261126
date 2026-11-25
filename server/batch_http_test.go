package server_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"previewtoken/server"
	"previewtoken/token"
)

func decodeBody(t *testing.T, res *http.Response) map[string]any {
	t.Helper()
	defer res.Body.Close()
	data, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]any{}
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("decode %q: %v", string(data), err)
	}
	return out
}

// TestThumbnailBatchConcurrentLoads issues one token per thumbnail and fires
// all requests at the same time, exactly like a page loading <img> elements.
// Every distinct token must succeed; every replay must be rejected.
func TestThumbnailBatchConcurrentLoads(t *testing.T) {
	env := newTestEnv(t)

	status, batch := env.post(t, "/api/preview/batch", map[string]any{
		"file": "gallery/team.png", "version": "v9", "user": "carol",
		"profiles": []string{"w64", "w128", "w256", "w512", "w1024", "orig"},
	})
	if status != http.StatusCreated {
		t.Fatalf("batch issue status=%d body=%v", status, batch)
	}
	urlsAny, _ := batch["urls"].([]any)
	if len(urlsAny) != 6 {
		t.Fatalf("expected 6 urls, got %d", len(urlsAny))
	}

	client := env.srv.Client()
	var wg sync.WaitGroup
	statuses := make(chan int, len(urlsAny)*2)

	load := func(u string) {
		defer wg.Done()
		res, err := client.Get(env.srv.URL + u + "&user=carol")
		if err != nil {
			t.Errorf("GET %s: %v", u, err)
			return
		}
		_, _ = io.Copy(io.Discard, res.Body)
		res.Body.Close()
		statuses <- res.StatusCode
	}

	// First wave: concurrent distinct thumbnail requests.
	for _, u := range urlsAny {
		wg.Add(1)
		go load(u.(string))
	}
	wg.Wait()

	// Second wave: immediate replays of the exact same URLs.
	for _, u := range urlsAny {
		wg.Add(1)
		go load(u.(string))
	}
	wg.Wait()
	close(statuses)

	var firstOK, replaysRejected int
	all := collect(statuses)
	if len(all) != 12 {
		t.Fatalf("got %d statuses", len(all))
	}
	for i, code := range all {
		// Channel interleaves waves; assert aggregate counts instead.
		_ = i
		if code == http.StatusOK {
			firstOK++
		} else if code == http.StatusUnauthorized {
			replaysRejected++
		} else {
			t.Fatalf("unexpected status %d", code)
		}
	}
	if firstOK != 6 {
		t.Fatalf("successful thumbnail loads = %d, want 6 (batch misjudged as replay?)", firstOK)
	}
	if replaysRejected != 6 {
		t.Fatalf("rejected replays = %d, want 6", replaysRejected)
	}
}

func collect(ch <-chan int) []int {
	var out []int
	for v := range ch {
		out = append(out, v)
	}
	return out
}

// TestSessionBatchGrantOverHTTP covers the page-token -> batch-grant flow.
func TestSessionBatchGrantOverHTTP(t *testing.T) {
	env := newTestEnv(t)

	_, page := env.post(t, "/api/preview/tokens", map[string]any{
		"file": "deck.key", "version": "v2", "user": "dana",
		"purpose": "page", "items": []string{"a", "b", "c", "d"},
	})
	pageToken, _ := page["token"].(string)

	status, session := env.post(t, "/api/preview/session", map[string]any{
		"token": pageToken,
	})
	if status != http.StatusCreated {
		t.Fatalf("session status=%d body=%v", status, session)
	}
	tpl, _ := session["thumbnail_url_template"].(string)
	if tpl == "" {
		t.Fatal("missing thumbnail_url_template")
	}

	// Re-exchanging the one-time page token must fail.
	status, again := env.post(t, "/api/preview/session", map[string]any{"token": pageToken})
	if status != http.StatusUnauthorized || again["reason"] != "replayed" {
		t.Fatalf("page token reuse = %d %v", status, again)
	}

	items := []string{"a", "b", "c", "d"}
	client := env.srv.Client()
	for _, item := range items {
		res, err := client.Get(env.srv.URL + replaceItem(tpl, item) + "&user=dana")
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(res.Body)
		res.Body.Close()
		if res.StatusCode != http.StatusOK {
			t.Fatalf("item %s status=%d body=%s", item, res.StatusCode, body)
		}
		if ct := res.Header.Get("Content-Type"); ct != "image/png" {
			t.Fatalf("item %s content-type=%q want image/png", item, ct)
		}
	}

	// Same item twice is a replay.
	res, _ := client.Get(env.srv.URL + replaceItem(tpl, "a"))
	res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("duplicate item status=%d want 401", res.StatusCode)
	}

	// Unknown item is forbidden.
	res, _ = client.Get(env.srv.URL + replaceItem(tpl, "evil"))
	res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("unknown item status=%d want 403", res.StatusCode)
	}
}

func replaceItem(tpl, item string) string {
	return strings.Replace(tpl, "{item}", item, 1)
}

// TestRestartKeepsUsedTokens verifies the os/encoding/json ledger keeps
// one-time state across a manager/server restart in a clean data file.
func TestRestartKeepsUsedTokens(t *testing.T) {
	dataFile := filepath.Join(t.TempDir(), "state", "tokens.json")
	secret := []byte("restart-secret-0123456789abcdef")

	mgr1, err := token.NewManager(secret, token.NewJSONStore(dataFile))
	if err != nil {
		t.Fatal(err)
	}
	srv1 := httptest.NewServer(server.New(mgr1).Handler())

	body, _ := json.Marshal(map[string]any{"file": "f", "version": "1", "user": "u"})
	res, err := http.Post(srv1.URL+"/api/preview/tokens", "application/json",
		bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	issued := decodeBody(t, res)
	tok, _ := issued["token"].(string)
	previewURL, _ := issued["preview_url"].(string)

	res, err = http.Get(srv1.URL + previewURL)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("first use status=%d", res.StatusCode)
	}
	srv1.Close()

	// Restart with the same JSON ledger and HMAC secret.
	mgr2, err := token.NewManager(secret, token.NewJSONStore(dataFile))
	if err != nil {
		t.Fatal(err)
	}
	srv2 := httptest.NewServer(server.New(mgr2).Handler())
	defer srv2.Close()

	status, resp := postJSON(t, srv2.URL+"/api/preview/verify", map[string]any{"token": tok})
	if status != http.StatusUnauthorized || resp["reason"] != "replayed" {
		t.Fatalf("after restart replay=%d %v", status, resp)
	}
}

func postJSON(t *testing.T, url string, body any) (int, map[string]any) {
	t.Helper()
	data, _ := json.Marshal(body)
	res, err := http.Post(url, "application/json", bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	out := decodeBody(t, res)
	return res.StatusCode, out
}
