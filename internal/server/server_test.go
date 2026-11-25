package server_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"testing"

	"fileshare/internal/keyring"
	"fileshare/internal/server"
	"fileshare/internal/store"
)

func newTestServer(t *testing.T) (http.Handler, *keyring.Keyring, string) {
	t.Helper()
	dataDir := t.TempDir()
	kr, err := keyring.Open(filepath.Join(dataDir, "keyring"), "alice")
	if err != nil {
		t.Fatal(err)
	}
	st := store.New(dataDir, kr)
	return server.New(st, kr).Handler(), kr, dataDir
}

func do(t *testing.T, h http.Handler, method, path string, body []byte, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestHTTPUploadRotateDownloadOldVersion(t *testing.T) {
	h, _, _ := newTestServer(t)

	rec := do(t, h, http.MethodPost, "/files/spec/versions",
		[]byte("v1 body"), map[string]string{"X-Creator": "alice", "X-Filename": "spec.md"})
	if rec.Code != http.StatusCreated {
		t.Fatalf("upload v1 status = %d: %s", rec.Code, rec.Body.String())
	}

	rec = do(t, h, http.MethodPost, "/files/spec/versions",
		[]byte("v2 body"), map[string]string{"X-Creator": "bob"})
	if rec.Code != http.StatusCreated {
		t.Fatalf("upload v2 status = %d", rec.Code)
	}

	rec = do(t, h, http.MethodPost, "/keys/rotate",
		mustJSON(t, map[string]string{"created_by": "carol"}),
		map[string]string{"Content-Type": "application/json"})
	if rec.Code != http.StatusCreated {
		t.Fatalf("rotate status = %d: %s", rec.Code, rec.Body.String())
	}

	rec = do(t, h, http.MethodPost, "/files/spec/versions",
		[]byte("v3 body"), map[string]string{"X-Creator": "carol"})
	if rec.Code != http.StatusCreated {
		t.Fatalf("upload v3 status = %d", rec.Code)
	}

	// The manifest keeps every version with its KEK version, checksum, creator.
	rec = do(t, h, http.MethodGet, "/files/spec/manifest", nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("manifest status = %d", rec.Code)
	}
	var manifest store.PublicManifest
	if err := json.Unmarshal(rec.Body.Bytes(), &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.Latest != 3 || len(manifest.Versions) != 3 {
		t.Fatalf("manifest = %+v", manifest)
	}
	wantKeyVersions := []int{1, 1, 2}
	for i, v := range manifest.Versions {
		if v.KeyVersion != wantKeyVersions[i] {
			t.Fatalf("v%d key version = %d, want %d", v.Number, v.KeyVersion, wantKeyVersions[i])
		}
		if v.PlainSHA256 == "" || v.CipherSHA256 == "" || v.CreatedBy == "" {
			t.Fatalf("v%d missing metadata: %+v", v.Number, v)
		}
	}

	// Any historical version can be downloaded, including pre-rotation ones.
	cases := map[int]string{1: "v1 body", 2: "v2 body", 3: "v3 body"}
	for number, want := range cases {
		rec = do(t, h, http.MethodGet,
			"/files/spec/versions/"+strconv.Itoa(number), nil, nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("download v%d status = %d: %s", number, rec.Code, rec.Body.String())
		}
		got, _ := io.ReadAll(rec.Body)
		if string(got) != want {
			t.Fatalf("v%d body = %q, want %q", number, got, want)
		}
	}

	rec = do(t, h, http.MethodGet, "/keys", nil, nil)
	var keys []keyring.Meta
	if err := json.Unmarshal(rec.Body.Bytes(), &keys); err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 {
		t.Fatalf("expected 2 KEK versions, got %d", len(keys))
	}
}

func TestHTTPDownloadUnknownVersion(t *testing.T) {
	h, _, _ := newTestServer(t)
	do(t, h, http.MethodPost, "/files/a/versions", []byte("x"),
		map[string]string{"X-Creator": "alice"})
	rec := do(t, h, http.MethodGet, "/files/a/versions/5", nil, nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
