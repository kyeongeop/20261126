package cleanup

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

// NewHandler builds the HTTP API for the cleanup service.
func NewHandler(service *Service) http.Handler {
	api := &apiHandler{service: service}
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", api.health)
	mux.HandleFunc("POST /api/v1/cleanup/previews", api.createPreview)
	mux.HandleFunc("GET /api/v1/cleanup/previews/{id}", api.getPreview)
	mux.HandleFunc("POST /api/v1/cleanup/previews/{id}/execute", api.executePreview)
	mux.HandleFunc("GET /api/v1/cleanup/runs/{id}", api.getRun)
	mux.HandleFunc("POST /api/v1/cleanup/runs/{id}/resume", api.resumeRun)
	mux.HandleFunc("GET /api/v1/cleanup/runs/{id}/manifest", api.getManifest)

	// Short aliases keep the API convenient for small admin clients.
	mux.HandleFunc("POST /api/cleanup/preview", api.createPreview)
	mux.HandleFunc("POST /api/cleanup/execute", api.executePreview)
	mux.HandleFunc("POST /api/cleanup/runs/{id}/resume", api.resumeRun)
	mux.HandleFunc("GET /api/cleanup/runs/{id}", api.getRun)
	mux.HandleFunc("GET /api/cleanup/runs/{id}/manifest", api.getManifest)
	mux.HandleFunc("GET /api/cleanup/previews/{id}", api.getPreview)
	return mux
}

type apiHandler struct {
	service *Service
}

func (h *apiHandler) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *apiHandler) createPreview(w http.ResponseWriter, _ *http.Request) {
	preview, err := h.service.CreatePreview()
	if err != nil {
		writeServiceError(w, err)
		return
	}
	w.Header().Set("Location", "/api/v1/cleanup/previews/"+preview.ID)
	writeJSON(w, http.StatusCreated, preview)
}

func (h *apiHandler) getPreview(w http.ResponseWriter, r *http.Request) {
	preview, err := h.service.GetPreview(r.PathValue("id"))
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, preview)
}

type executeRequest struct {
	PreviewID string `json:"preview_id"`
}

func (h *apiHandler) executePreview(w http.ResponseWriter, r *http.Request) {
	previewID := r.PathValue("id")
	if previewID == "" {
		var request executeRequest
		if err := decodeOptionalJSON(w, r, &request); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
			return
		}
		previewID = request.PreviewID
	}
	if strings.TrimSpace(previewID) == "" {
		writeError(w, http.StatusBadRequest, "preview_required", "preview_id is required; preview before executing")
		return
	}
	run, err := h.service.ExecutePreview(previewID)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	w.Header().Set("Location", "/api/v1/cleanup/runs/"+run.ID)
	writeJSON(w, http.StatusOK, run)
}

type resumeRequest struct {
	ItemIDs []string `json:"item_ids"`
}

func (h *apiHandler) resumeRun(w http.ResponseWriter, r *http.Request) {
	var request resumeRequest
	if err := decodeOptionalJSON(w, r, &request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	run, err := h.service.ResumeRun(r.PathValue("id"), request.ItemIDs)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, run)
}

func (h *apiHandler) getRun(w http.ResponseWriter, r *http.Request) {
	run, err := h.service.GetRun(r.PathValue("id"))
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, run)
}

func (h *apiHandler) getManifest(w http.ResponseWriter, r *http.Request) {
	run, err := h.service.GetRun(r.PathValue("id"))
	if err != nil {
		writeServiceError(w, err)
		return
	}
	var data []byte
	if run.ManifestPath != "" {
		data, err = os.ReadFile(run.ManifestPath)
	}
	if len(data) == 0 || err != nil {
		data, err = json.MarshalIndent(run, "", "  ")
	}
	if err != nil {
		writeServiceError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s-manifest.json"`, run.ID))
	if run.ManifestPath != "" {
		w.Header().Set("X-Manifest-Path", run.ManifestPath)
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(append(data, '\n'))
}

func decodeOptionalJSON(w http.ResponseWriter, r *http.Request, target any) error {
	if r.Body == nil {
		return nil
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	if err := decoder.Decode(target); err != nil {
		if errors.Is(err, io.EOF) {
			return nil
		}
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("request body must contain one JSON object")
	}
	return nil
}

func writeServiceError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", err.Error())
	case errors.Is(err, ErrStalePreview):
		writeError(w, http.StatusConflict, "stale_preview", err.Error())
	case errors.Is(err, ErrInvalidFilter):
		writeError(w, http.StatusBadRequest, "invalid_filter", err.Error())
	default:
		writeError(w, http.StatusInternalServerError, "internal_error", err.Error())
	}
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]any{
		"error": map[string]string{
			"code":    code,
			"message": message,
		},
	})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	encoder := json.NewEncoder(w)
	encoder.SetEscapeHTML(false)
	_ = encoder.Encode(value)
}
