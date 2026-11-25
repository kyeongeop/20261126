package httpapi

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"fileshare/internal/timeline"
)

// eventRequest is the JSON body for single and batch ingestion.
type eventRequest struct {
	ClientEventID string            `json:"client_event_id"`
	Action        string            `json:"action"`
	ActorID       string            `json:"actor_id"`
	OccurredAt    string            `json:"occurred_at"`
	VersionID     string            `json:"version_id"`
	Details       map[string]string `json:"details"`
}

func (r eventRequest) toInput(fileID string) (timeline.IngestInput, error) {
	action, ok := timeline.ParseAction(r.Action)
	if !ok {
		return timeline.IngestInput{}, errors.New("unknown or missing action")
	}
	occurred := time.Time{}
	if strings.TrimSpace(r.OccurredAt) != "" {
		parsed, err := parseTime(r.OccurredAt)
		if err != nil {
			return timeline.IngestInput{}, errors.New("occurred_at must be RFC3339")
		}
		occurred = parsed
	}
	return timeline.IngestInput{
		ClientEventID: r.ClientEventID,
		FileID:        fileID,
		Action:        action,
		ActorID:       r.ActorID,
		OccurredAt:    occurred,
		VersionID:     r.VersionID,
		Details:       r.Details,
	}, nil
}

func parseTime(raw string) (time.Time, error) {
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02 15:04:05"} {
		if t, err := time.Parse(layout, strings.TrimSpace(raw)); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, errors.New("invalid timestamp")
}

// parseFilter builds a timeline.Filter from query parameters:
// user, action, version, from/to (RFC3339) and limit.
func parseFilter(r *http.Request, fileID string) (timeline.Filter, int, error) {
	f := timeline.Filter{FileID: fileID, User: strings.TrimSpace(r.URL.Query().Get("user"))}
	if raw := strings.TrimSpace(r.URL.Query().Get("action")); raw != "" {
		action, ok := timeline.ParseAction(raw)
		if !ok {
			return f, 0, errors.New("unknown action filter")
		}
		f.Action = action
	}
	f.VersionID = strings.TrimSpace(r.URL.Query().Get("version"))
	if raw := r.URL.Query().Get("from"); raw != "" {
		t, err := parseTime(raw)
		if err != nil {
			return f, 0, errors.New("from must be RFC3339")
		}
		f.From = t
	}
	if raw := r.URL.Query().Get("to"); raw != "" {
		t, err := parseTime(raw)
		if err != nil {
			return f, 0, errors.New("to must be RFC3339")
		}
		f.To = t
	}
	limit := 0
	if raw := r.URL.Query().Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 0 {
			return f, 0, errors.New("limit must be a non-negative integer")
		}
		limit = n
	}
	return f, limit, nil
}

func (s *Server) handleListFiles(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"files": s.store.ListFiles()})
}

func (s *Server) handleGetFile(w http.ResponseWriter, r *http.Request) {
	info, err := s.store.GetFile(r.PathValue("fileID"))
	if err != nil {
		respondStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, info)
}

func (s *Server) handleTimeline(w http.ResponseWriter, r *http.Request) {
	fileID := r.PathValue("fileID")
	if _, err := s.store.GetFile(fileID); err != nil {
		respondStoreError(w, err)
		return
	}
	filter, limit, err := parseFilter(r, fileID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_filter", err.Error())
		return
	}
	page, err := s.store.List(filter, limit)
	if err != nil {
		respondStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, page)
}

func (s *Server) handleVersions(w http.ResponseWriter, r *http.Request) {
	info, err := s.store.GetFile(r.PathValue("fileID"))
	if err != nil {
		respondStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"file_id": info.FileID, "versions": info.Versions})
}

func (s *Server) handleIngest(w http.ResponseWriter, r *http.Request) {
	var req eventRequest
	if err := decodeBody(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "bad_body", err.Error())
		return
	}
	input, err := req.toInput(r.PathValue("fileID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_event", err.Error())
		return
	}
	result, err := s.store.Ingest(input)
	if err != nil {
		respondStoreError(w, err)
		return
	}
	status := http.StatusCreated
	if result.Duplicate || result.Suppressed {
		status = http.StatusOK
	}
	writeJSON(w, status, map[string]any{
		"event":      result.Event,
		"duplicate":  result.Duplicate,
		"suppressed": result.Suppressed,
	})
}

type batchRequest struct {
	FileID string         `json:"file_id"`
	Events []eventRequest `json:"events"`
}

type batchItem struct {
	Event      timeline.Event `json:"event"`
	Duplicate  bool           `json:"duplicate"`
	Suppressed bool           `json:"suppressed"`
	Error      string         `json:"error,omitempty"`
}

func (s *Server) handleBatchIngest(w http.ResponseWriter, r *http.Request) {
	var req batchRequest
	if err := decodeBody(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "bad_body", err.Error())
		return
	}
	if len(req.Events) == 0 {
		writeError(w, http.StatusBadRequest, "bad_body", "events must not be empty")
		return
	}
	items := make([]batchItem, 0, len(req.Events))
	failed := 0
	for _, evt := range req.Events {
		input, err := evt.toInput(strings.TrimSpace(req.FileID))
		if err != nil || input.FileID == "" {
			failed++
			message := "invalid event"
			if err != nil {
				message = err.Error()
			}
			items = append(items, batchItem{Error: message})
			continue
		}
		result, err := s.store.Ingest(input)
		if err != nil {
			failed++
			items = append(items, batchItem{Error: err.Error()})
			continue
		}
		items = append(items, batchItem{
			Event:      result.Event,
			Duplicate:  result.Duplicate,
			Suppressed: result.Suppressed,
		})
	}
	status := http.StatusCreated
	if failed == len(items) {
		status = http.StatusBadRequest
	}
	writeJSON(w, status, map[string]any{"ingested": len(items) - failed, "results": items})
}

func (s *Server) handleGetEvent(w http.ResponseWriter, r *http.Request) {
	ev, err := s.store.Get(r.PathValue("dedupKey"))
	if err != nil {
		respondStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, ev)
}

func (s *Server) handleDeleteEvent(w http.ResponseWriter, r *http.Request) {
	if err := s.store.Delete(r.PathValue("dedupKey")); err != nil {
		respondStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"dedup_key": r.PathValue("dedupKey"),
		"status":    "deleted",
	})
}

func respondStoreError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, timeline.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", err.Error())
	case errors.Is(err, timeline.ErrDeleted):
		writeError(w, http.StatusGone, "deleted", err.Error())
	case errors.Is(err, timeline.ErrInvalid):
		writeError(w, http.StatusBadRequest, "invalid", err.Error())
	default:
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
	}
}
