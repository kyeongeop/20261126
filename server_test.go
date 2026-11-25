package idconsole

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newTestServer(t *testing.T) (*httptest.Server, *Store) {
	t.Helper()
	store, _, err := SeedData()
	if err != nil {
		t.Fatalf("seed data: %v", err)
	}
	return httptest.NewServer(NewServer(store)), store
}

func doJSON(t *testing.T, method, url, token string, body io.Reader) (int, map[string]any) {
	t.Helper()
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	defer resp.Body.Close()
	decoded := map[string]any{}
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &decoded); err != nil {
			t.Fatalf("decode %q: %v", string(raw), err)
		}
	}
	return resp.StatusCode, decoded
}

func login(t *testing.T, baseURL, username, password string) (int, string) {
	t.Helper()
	body := `{"username":"` + username + `","password":"` + password + `"}`
	status, payload := doJSON(t, http.MethodPost, baseURL+"/api/login", "", stringReader(body))
	token, _ := payload["token"].(string)
	return status, token
}

func stringReader(s string) io.Reader {
	return strings.NewReader(s)
}

func intField(t *testing.T, payload map[string]any, key string) int {
	t.Helper()
	value, ok := payload[key].(float64)
	if !ok {
		t.Fatalf("expected numeric field %q in %v", key, payload)
	}
	return int(value)
}

func stringField(t *testing.T, payload map[string]any, key string) string {
	t.Helper()
	value, ok := payload[key].(string)
	if !ok {
		t.Fatalf("expected string field %q in %v", key, payload)
	}
	return value
}
