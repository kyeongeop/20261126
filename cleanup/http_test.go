package cleanup

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHTTPPreviewExecuteAndManifest(t *testing.T) {
	env := newTestEnvironment(t)
	service := env.service(t, sequentialIDs("http"))
	handler := NewHandler(service)

	response := request(t, handler, http.MethodPost, "/api/v1/cleanup/previews", nil)
	if response.Code != http.StatusCreated {
		t.Fatalf("preview status = %d: %s", response.Code, response.Body.String())
	}
	var preview Preview
	decodeResponse(t, response, &preview)
	if preview.ID == "" || preview.Summary.ByCategory[CategoryDirectoryMoved] != 1 {
		t.Fatalf("unexpected preview: %+v", preview)
	}

	response = request(t, handler, http.MethodGet, "/api/v1/cleanup/previews/"+preview.ID, nil)
	if response.Code != http.StatusOK {
		t.Fatalf("get preview status = %d", response.Code)
	}

	response = request(t, handler, http.MethodPost, "/api/cleanup/execute", nil)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("execute without preview status = %d, want 400", response.Code)
	}

	response = request(t, handler, http.MethodPost, "/api/v1/cleanup/previews/"+preview.ID+"/execute", nil)
	if response.Code != http.StatusOK {
		t.Fatalf("execute status = %d: %s", response.Code, response.Body.String())
	}
	var run CleanupRun
	decodeResponse(t, response, &run)
	if run.Status != RunCompleted || run.ManifestPath == "" {
		t.Fatalf("unexpected run: %+v", run)
	}

	response = request(t, handler, http.MethodGet, "/api/v1/cleanup/runs/"+run.ID, nil)
	if response.Code != http.StatusOK {
		t.Fatalf("get run status = %d", response.Code)
	}

	response = request(t, handler, http.MethodGet, "/api/v1/cleanup/runs/"+run.ID+"/manifest", nil)
	if response.Code != http.StatusOK {
		t.Fatalf("manifest status = %d: %s", response.Code, response.Body.String())
	}
	if got := response.Header().Get("Content-Disposition"); got == "" {
		t.Fatal("manifest response has no Content-Disposition")
	}
	var manifest CleanupRun
	decodeResponse(t, response, &manifest)
	if manifest.ID != run.ID || len(manifest.Items) != 4 {
		t.Fatalf("manifest response mismatch: %+v", manifest)
	}

	response = request(t, handler, http.MethodPost, "/api/v1/cleanup/previews/"+preview.ID+"/execute", nil)
	if response.Code != http.StatusConflict {
		t.Fatalf("stale execute status = %d, want 409", response.Code)
	}

	response = request(t, handler, http.MethodPost, "/api/v1/cleanup/runs/"+run.ID+"/resume", nil)
	if response.Code != http.StatusOK {
		t.Fatalf("resume completed status = %d", response.Code)
	}
	var resumed CleanupRun
	decodeResponse(t, response, &resumed)
	if resumed.Status != RunCompleted || resumed.Round != 1 {
		t.Fatalf("completed run was resumed: %+v", resumed)
	}
}

func TestHTTPExecuteByAliasBody(t *testing.T) {
	env := newTestEnvironment(t)
	service := env.service(t, sequentialIDs("alias"))
	handler := NewHandler(service)
	preview, err := service.CreatePreview()
	if err != nil {
		t.Fatalf("CreatePreview: %v", err)
	}

	body, err := json.Marshal(executeRequest{PreviewID: preview.ID})
	if err != nil {
		t.Fatal(err)
	}
	response := request(t, handler, http.MethodPost, "/api/cleanup/execute", bytes.NewReader(body))
	if response.Code != http.StatusOK {
		t.Fatalf("alias execute status = %d: %s", response.Code, response.Body.String())
	}
	var run CleanupRun
	decodeResponse(t, response, &run)
	if run.PreviewID != preview.ID {
		t.Fatalf("run preview id = %q, want %q", run.PreviewID, preview.ID)
	}
}

func request(t *testing.T, handler http.Handler, method, target string, body *bytes.Reader) *httptest.ResponseRecorder {
	t.Helper()
	var requestBody *bytes.Reader
	if body == nil {
		requestBody = bytes.NewReader(nil)
	} else {
		requestBody = body
	}
	req := httptest.NewRequest(method, target, requestBody)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	return recorder
}

func decodeResponse(t *testing.T, response *httptest.ResponseRecorder, target any) {
	t.Helper()
	if err := json.Unmarshal(response.Body.Bytes(), target); err != nil {
		t.Fatalf("decode response %q: %v", response.Body.String(), err)
	}
}
