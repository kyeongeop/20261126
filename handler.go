package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Server 聚合存储与路由。
type Server struct {
	store *Store
}

func NewServer(store *Store) *Server {
	s := &Server{store: store}
	return s
}

func (s *Server) Routes() *http.ServeMux {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /api/health", s.handleHealth)
	mux.HandleFunc("GET /api/meta", s.handleMeta)
	mux.HandleFunc("GET /api/shares", s.handleListShares)

	// 预览：提交前展示受影响文件数。GET 用查询参数，POST 用 JSON 条件。
	mux.HandleFunc("/api/shares/revoke/preview", s.handlePreview)
	mux.HandleFunc("/api/admin/revocations/preview", s.handlePreview)

	// 执行批量撤销（需要原因），事务化全成或整体回滚。
	mux.HandleFunc("POST /api/shares/batch-revoke", s.handleRevoke)
	mux.HandleFunc("POST /api/admin/revocations", s.handleRevoke)
	mux.HandleFunc("POST /api/batch-revoke", s.handleRevoke)

	// 审计记录查询，撤销后长期保留。
	mux.HandleFunc("GET /api/audits", s.handleListAudits)
	mux.HandleFunc("GET /api/admin/audits", s.handleListAudits)
	mux.HandleFunc("GET /api/admin/revocations", s.handleListAudits)
	mux.HandleFunc("GET /api/audits/{batchID}", s.handleGetAudit)
	mux.HandleFunc("GET /api/admin/audits/{batchID}", s.handleGetAudit)

	mux.HandleFunc("GET /{$}", s.handleIndex)
	return mux
}

type errorBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]any{"error": errorBody{Code: code, Message: message}})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "ok",
		"time":   time.Now().UTC(),
	})
}

func (s *Server) handleMeta(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.store.GetMeta())
}

func (s *Server) handleListShares(w http.ResponseWriter, r *http.Request) {
	f, err := filterFromQuery(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_filter", err.Error())
		return
	}
	items := s.store.ListShares(f)
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "total": len(items)})
}

func (s *Server) handlePreview(w http.ResponseWriter, r *http.Request) {
	f, err := s.resolveFilter(w, r)
	if err != nil {
		if errors.Is(err, errMethodNotAllowed) {
			writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", err.Error())
			return
		}
		writeError(w, http.StatusBadRequest, "invalid_filter", err.Error())
		return
	}
	preview := s.store.Preview(f)
	writeJSON(w, http.StatusOK, preview)
}

type revokeHTTPRequest struct {
	filterDTO
	Criteria     *filterDTO `json:"criteria"`
	Filters      *filterDTO `json:"filters"`
	Reason       string     `json:"reason"`
	RevokeReason string     `json:"revoke_reason"`
	Comment      string     `json:"comment"`
	Operator     string     `json:"operator"`
	Admin        string     `json:"admin"`
}

func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req revokeHTTPRequest
	if r.ContentLength != 0 {
		dec := json.NewDecoder(r.Body)
		if err := dec.Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_json", "请求体不是合法 JSON: "+err.Error())
			return
		}
	}

	dto := req.filterDTO
	if req.Criteria != nil {
		dto = *req.Criteria
	} else if req.Filters != nil {
		dto = *req.Filters
	}
	f, err := dto.toFilter()
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_filter", err.Error())
		return
	}

	reason := firstNonEmpty(req.Reason, req.RevokeReason, req.Comment)
	if strings.TrimSpace(reason) == "" {
		writeError(w, http.StatusBadRequest, "reason_required",
			"必须填写撤销原因（reason 字段），该原因会写入审计记录")
		return
	}
	if len([]rune(reason)) > 500 {
		writeError(w, http.StatusBadRequest, "reason_too_long", "撤销原因不能超过 500 字")
		return
	}
	operator := firstNonEmpty(req.Operator, req.Admin)

	result, err := s.store.BatchRevoke(RevokeInput{
		Filter:   f,
		Reason:   reason,
		Operator: operator,
	})
	if err != nil {
		switch {
		case errors.Is(err, ErrNothingToRevoke):
			writeError(w, http.StatusConflict, "nothing_to_revoke", err.Error())
		default:
			writeError(w, http.StatusInternalServerError, "commit_failed_rolled_back",
				"批量撤销未能提交，所有变更已整体回滚，未撤销任何链接: "+err.Error())
		}
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleListAudits(w http.ResponseWriter, r *http.Request) {
	items := s.store.ListAudits()
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "total": len(items)})
}

func (s *Server) handleGetAudit(w http.ResponseWriter, r *http.Request) {
	batchID := r.PathValue("batchID")
	ev, err := s.store.GetAudit(batchID)
	if err != nil {
		writeError(w, http.StatusNotFound, "audit_not_found", "审计记录不存在: "+batchID)
		return
	}
	writeJSON(w, http.StatusOK, ev)
}

// resolveFilter 同时支持 GET 查询参数与 POST JSON 条件（预览接口两种都接受）。
func (s *Server) resolveFilter(w http.ResponseWriter, r *http.Request) (Filter, error) {
	if r.Method == http.MethodGet {
		return filterFromQuery(r)
	}
	if r.Method != http.MethodPost {
		return Filter{}, errMethodNotAllowed
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req revokeHTTPRequest
	if r.ContentLength != 0 {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			return Filter{}, fmt.Errorf("请求体不是合法 JSON: %w", err)
		}
	}
	dto := req.filterDTO
	if req.Criteria != nil {
		dto = *req.Criteria
	} else if req.Filters != nil {
		dto = *req.Filters
	}
	return dto.toFilter()
}

var errMethodNotAllowed = errors.New("仅支持 GET 或 POST")

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
