package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newTestAuth() *authConfig {
	return &authConfig{users: map[string]credential{
		"publisher": {
			passwordHash: sha256.Sum256([]byte("publisher-pass")),
			role:         rolePublisher,
		},
		"admin": {
			passwordHash: sha256.Sum256([]byte("admin-pass")),
			role:         roleAdmin,
		},
	}}
}

func newTestServer(t *testing.T) (*Store, *httptest.Server) {
	t.Helper()
	store := newTestStore(t)
	app, err := NewApp(store, newTestAuth())
	if err != nil {
		t.Fatalf("NewApp: %v", err)
	}
	return store, httptest.NewServer(app)
}

func uploadRequest(t *testing.T, target string, fields map[string]string, artifact []byte, user, password string) *http.Request {
	t.Helper()
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	for name, value := range fields {
		if err := writer.WriteField(name, value); err != nil {
			t.Fatalf("write field: %v", err)
		}
	}
	part, err := writer.CreateFormFile("package", "package.tar")
	if err != nil {
		t.Fatalf("create file part: %v", err)
	}
	if _, err := part.Write(artifact); err != nil {
		t.Fatalf("write file part: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close multipart writer: %v", err)
	}
	request, err := http.NewRequest(http.MethodPost, target, &body)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	request.Header.Set("Content-Type", writer.FormDataContentType())
	request.SetBasicAuth(user, password)
	return request
}

func doRequest(t *testing.T, request *http.Request) (*http.Response, []byte) {
	t.Helper()
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	return response, body
}

func TestAPIUploadAndDuplicateConflict(t *testing.T) {
	store, server := newTestServer(t)
	defer server.Close()
	artifact := testTar(t, map[string]string{"README": "release\n"})

	response, body := doRequest(t, uploadRequest(t, server.URL+"/api/packages", map[string]string{
		"name": "demo", "version": "1.0.0",
	}, artifact, "publisher", "publisher-pass"))
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("upload status = %d, body = %s", response.StatusCode, body)
	}
	var published publicationResponse
	if err := json.Unmarshal(body, &published); err != nil {
		t.Fatalf("decode upload response: %v", err)
	}
	if published.ContentDigest != digestBytes(artifact) {
		t.Fatalf("response digest = %q", published.ContentDigest)
	}
	if !published.ServerVerification.Valid {
		t.Fatalf("response verification invalid: %+v", published.ServerVerification)
	}

	response, body = doRequest(t, uploadRequest(t, server.URL+"/api/packages/demo/1.0.0", map[string]string{
		"name": "demo", "version": "1.0.0",
	}, testTar(t, map[string]string{"README": "replacement\n"}), "publisher", "publisher-pass"))
	if response.StatusCode != http.StatusConflict {
		t.Fatalf("duplicate status = %d, body = %s", response.StatusCode, body)
	}
	var apiErr struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &apiErr); err != nil {
		t.Fatalf("decode conflict: %v", err)
	}
	if apiErr.Error.Code != "version_exists" {
		t.Fatalf("conflict code = %q", apiErr.Error.Code)
	}
	loaded, err := store.Release("demo", "1.0.0")
	if err != nil {
		t.Fatalf("load release: %v", err)
	}
	if loaded.ContentDigest != digestBytes(artifact) {
		t.Fatalf("published content was overwritten")
	}
}

func TestAdminRepairAndRoleBoundaries(t *testing.T) {
	store, server := newTestServer(t)
	defer server.Close()
	original := testTar(t, map[string]string{"start.sh": "broken\n"})

	response, body := doRequest(t, uploadRequest(t, server.URL+"/api/packages", map[string]string{
		"name": "tool", "version": "1.0.0",
	}, original, "publisher", "publisher-pass"))
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("publish original status = %d, body = %s", response.StatusCode, body)
	}

	response, body = doRequest(t, uploadRequest(t, server.URL+"/api/packages", map[string]string{
		"name": "tool", "version": "1.0.1",
	}, testTar(t, map[string]string{"start.sh": "normal\n"}), "admin", "admin-pass"))
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("admin non-repair status = %d, body = %s", response.StatusCode, body)
	}
	var apiErr struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &apiErr); err != nil {
		t.Fatalf("decode admin error: %v", err)
	}
	if apiErr.Error.Code != "admin_repair_only" {
		t.Fatalf("admin error code = %q", apiErr.Error.Code)
	}

	response, body = doRequest(t, uploadRequest(t, server.URL+"/api/packages", map[string]string{
		"name": "tool", "version": "1.0.1", "repair_of": "1.0.0", "reason": "fix start",
	}, testTar(t, map[string]string{"start.sh": "fixed\n"}), "publisher", "publisher-pass"))
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("publisher repair status = %d, body = %s", response.StatusCode, body)
	}

	response, body = doRequest(t, uploadRequest(t, server.URL+"/api/packages/tool/1.0.1/repair", map[string]string{
		"replaces": "1.0.0", "reason": "fix start",
	}, testTar(t, map[string]string{"start.sh": "fixed\n"}), "admin", "admin-pass"))
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("admin repair status = %d, body = %s", response.StatusCode, body)
	}
	var repaired publicationResponse
	if err := json.Unmarshal(body, &repaired); err != nil {
		t.Fatalf("decode repair response: %v", err)
	}
	if repaired.Name != "tool" || repaired.Version != "1.0.1" {
		t.Fatalf("repair identity = %s %s", repaired.Name, repaired.Version)
	}
	if repaired.Repair == nil || repaired.Repair.OfVersion != "1.0.0" {
		t.Fatalf("repair reference = %+v", repaired.Repair)
	}
	if !repaired.ServerVerification.Valid {
		t.Fatalf("repair signature invalid: %+v", repaired.ServerVerification)
	}

	loaded, err := store.Release("tool", "1.0.0")
	if err != nil {
		t.Fatalf("load original: %v", err)
	}
	if loaded.ContentDigest != digestBytes(original) {
		t.Fatalf("administrator changed original release")
	}

	response, body = doRequest(t, uploadRequest(t, server.URL+"/api/packages/tool/1.0.1/repair", map[string]string{
		"replaces": "1.0.0", "reason": "again",
	}, testTar(t, map[string]string{"start.sh": "again\n"}), "admin", "admin-pass"))
	if response.StatusCode != http.StatusConflict {
		t.Fatalf("duplicate repair status = %d, body = %s", response.StatusCode, body)
	}
}

func TestDownloadPageShowsVerificationAndRejectsTampering(t *testing.T) {
	store, server := newTestServer(t)
	defer server.Close()
	artifact := testTar(t, map[string]string{"payload.txt": "trusted\n"})

	response, body := doRequest(t, uploadRequest(t, server.URL+"/api/packages", map[string]string{
		"name": "secure", "version": "2.0.0",
	}, artifact, "publisher", "publisher-pass"))
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("upload status = %d, body = %s", response.StatusCode, body)
	}

	request, _ := http.NewRequest(http.MethodGet, server.URL+"/packages/secure/2.0.0", nil)
	response, body = doRequest(t, request)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("release page status = %d", response.StatusCode)
	}
	if !bytes.Contains(body, []byte("签名验证通过")) {
		t.Fatalf("release page missing valid signature status:\n%s", body)
	}

	request, _ = http.NewRequest(http.MethodGet, server.URL+"/packages/secure/2.0.0/download", nil)
	response, downloaded := doRequest(t, request)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("download status = %d, body = %s", response.StatusCode, downloaded)
	}
	if !bytes.Equal(downloaded, artifact) {
		t.Fatalf("downloaded bytes differ from uploaded archive")
	}
	if response.Header.Get("X-Signature-Verification") != "valid" {
		t.Fatalf("download signature header = %q", response.Header.Get("X-Signature-Verification"))
	}

	loaded, err := store.Release("secure", "2.0.0")
	if err != nil {
		t.Fatalf("load release: %v", err)
	}
	objectPath := filepath.Join(store.objectDir, strings.TrimPrefix(loaded.ContentDigest, "sha256:")+".tar")
	if err := os.WriteFile(objectPath, []byte("tampered archive"), 0o644); err != nil {
		t.Fatalf("tamper object: %v", err)
	}

	request, _ = http.NewRequest(http.MethodGet, server.URL+"/packages/secure/2.0.0", nil)
	response, body = doRequest(t, request)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("tampered page status = %d", response.StatusCode)
	}
	if !bytes.Contains(body, []byte("签名验证失败")) {
		t.Fatalf("tampered page missing failed signature status:\n%s", body)
	}
	request, _ = http.NewRequest(http.MethodGet, server.URL+"/packages/secure/2.0.0/download", nil)
	response, body = doRequest(t, request)
	if response.StatusCode != http.StatusConflict {
		t.Fatalf("tampered download status = %d, body = %s", response.StatusCode, body)
	}
}

func TestUploadRequiresAuthentication(t *testing.T) {
	_, server := newTestServer(t)
	defer server.Close()
	artifact := testTar(t, map[string]string{"README": "content"})
	request := uploadRequest(t, server.URL+"/api/packages", map[string]string{
		"name": "demo", "version": "1.0.0",
	}, artifact, "", "")
	request.SetBasicAuth("", "")
	request.Header.Del("Authorization")

	response, body := doRequest(t, request)
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status = %d, body = %s", response.StatusCode, body)
	}
	if response.Header.Get("WWW-Authenticate") == "" {
		t.Fatalf("missing WWW-Authenticate header")
	}
}

func TestRawTarUpload(t *testing.T) {
	store, server := newTestServer(t)
	defer server.Close()
	artifact := testTar(t, map[string]string{"README": "raw upload\n"})
	request, err := http.NewRequest(http.MethodPost, server.URL+"/api/packages", bytes.NewReader(artifact))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	request.Header.Set("Content-Type", "application/x-tar")
	request.Header.Set("X-Package-Name", "raw-package")
	request.Header.Set("X-Package-Version", "1.0.0")
	request.SetBasicAuth("publisher", "publisher-pass")

	response, body := doRequest(t, request)
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("raw upload status = %d, body = %s", response.StatusCode, body)
	}
	release, err := store.Release("raw-package", "1.0.0")
	if err != nil {
		t.Fatalf("load raw release: %v", err)
	}
	if release.ContentDigest != digestBytes(artifact) {
		t.Fatalf("raw upload digest mismatch")
	}
}
