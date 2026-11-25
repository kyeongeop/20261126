// Package server wires the versioned encrypted store to a net/http API.
package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"

	"fileshare/internal/keyring"
	"fileshare/internal/store"
)

// Server holds the HTTP handlers and their dependencies.
type Server struct {
	store *store.Store
	kr    *keyring.Keyring
}

// New builds the Server and its routed *http.ServeMux.
func New(st *store.Store, kr *keyring.Keyring) *Server {
	return &Server{store: st, kr: kr}
}

// Handler returns the routed HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /files", s.listFiles)
	mux.HandleFunc("POST /files/{id}/versions", s.uploadVersion)
	mux.HandleFunc("GET /files/{id}/manifest", s.getManifest)
	mux.HandleFunc("GET /files/{id}/versions/{number}", s.downloadVersion)
	mux.HandleFunc("GET /keys", s.listKeys)
	mux.HandleFunc("POST /keys/rotate", s.rotateKey)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	return mux
}

func (s *Server) listFiles(w http.ResponseWriter, r *http.Request) {
	files, err := s.store.ListFiles()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, files)
}

func (s *Server) uploadVersion(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	creator := r.Header.Get("X-Creator")
	if creator == "" {
		writeError(w, http.StatusBadRequest, errors.New("missing X-Creator header"))
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 256<<20))
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if len(body) == 0 {
		writeError(w, http.StatusBadRequest, errors.New("empty file body"))
		return
	}
	entry, err := s.store.AddVersion(
		id,
		r.Header.Get("X-Filename"),
		creator,
		r.Header.Get("X-Note"),
		body,
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusCreated, entry)
}

func (s *Server) getManifest(w http.ResponseWriter, r *http.Request) {
	m, err := s.store.PublicManifest(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if m.Latest == 0 {
		writeError(w, http.StatusNotFound, store.ErrNotFound)
		return
	}
	writeJSON(w, http.StatusOK, m)
}

func (s *Server) downloadVersion(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	number, err := strconv.Atoi(r.PathValue("number"))
	if err != nil || number < 1 {
		writeError(w, http.StatusBadRequest, errors.New("invalid version number"))
		return
	}
	plaintext, entry, err := s.store.ReadVersion(id, number)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, err)
			return
		}
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition",
		fmt.Sprintf(`attachment; filename="%s-v%d"`, id, number))
	w.Header().Set("X-Key-Version", strconv.Itoa(entry.KeyVersion))
	w.Header().Set("X-Plain-SHA256", entry.PlainSHA256)
	w.Header().Set("X-Cipher-SHA256", entry.CipherSHA256)
	w.Header().Set("X-Created-By", entry.CreatedBy)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(plaintext)
}

type rotateRequest struct {
	CreatedBy string `json:"created_by"`
}

func (s *Server) rotateKey(w http.ResponseWriter, r *http.Request) {
	var req rotateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if req.CreatedBy == "" {
		writeError(w, http.StatusBadRequest, errors.New("missing created_by"))
		return
	}
	meta, err := s.kr.Rotate(req.CreatedBy)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusCreated, meta)
}

func (s *Server) listKeys(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.kr.List())
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]string{"error": err.Error()})
}
