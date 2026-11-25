package server_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"previewtoken/server"
	"previewtoken/token"
)

func TestPreviewServesRegisteredFileBytes(t *testing.T) {
	dir := t.TempDir()
	content := []byte("real preview bytes for quarterly plan\n")
	filePath := filepath.Join(dir, "plans", "q4.pdf", "versions", "v7")
	if err := os.MkdirAll(filepath.Dir(filePath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filePath, content, 0o644); err != nil {
		t.Fatal(err)
	}

	secret := []byte("content-test-secret-0123456789abc")
	mgr, err := token.NewManager(secret, token.NewJSONStore(filepath.Join(t.TempDir(), "t.json")))
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(server.New(mgr, server.WithContentDir(dir)).Handler())
	defer ts.Close()

	raw, _, err := mgr.Issue(token.IssueRequest{
		File: "plans/q4.pdf", Version: "v7", User: "alice", Purpose: token.PurposePreview,
	})
	if err != nil {
		t.Fatal(err)
	}

	res, err := http.Get(ts.URL + "/preview?token=" + raw)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	data, _ := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status=%d body=%s", res.StatusCode, data)
	}
	if string(data) != string(content) {
		t.Fatalf("content mismatch: %q", data)
	}
}
