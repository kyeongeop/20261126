package server

import (
	"net/http"
	"strconv"
	"time"

	"previewtoken/token"
)

func previewURLFor(purpose, raw string) string {
	switch purpose {
	case token.PurposeThumbnail:
		return "/preview/thumbnail?token=" + raw
	case token.PurposePage:
		return "/demo?page_token=" + raw
	default:
		return "/preview?token=" + raw
	}
}

func (s *Server) handleIssueToken(w http.ResponseWriter, r *http.Request) {
	var req issueTokenRequest
	if r.ContentLength != 0 {
		if err := decodeJSON(w, r, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, errorResponse{Error: err.Error(), Reason: "bad_json"})
			return
		}
	}

	purpose := req.Purpose
	if purpose == "" {
		purpose = token.PurposePreview
	}
	issue := token.IssueRequest{
		File:      req.file(),
		Version:   req.version(),
		User:      req.user(),
		Purpose:   purpose,
		TTL:       req.ttl(),
		Item:      req.Item,
		Items:     req.Items,
		ExpiresAt: timeOrZero(req.ExpiresAt),
	}
	raw, claims, err := s.mgr.Issue(issue)
	if err != nil {
		s.writeTokenError(w, err)
		return
	}

	url := previewURLFor(purpose, raw)
	writeJSON(w, http.StatusCreated, tokenResponse{
		Token:       raw,
		AccessToken: raw,
		TokenType:   "one-time-preview-token",
		Claims:      claims,
		ExpiresAt:   claims.ExpiresAt,
		PreviewURL:  url,
		URL:         url,
	})
}

type batchItemRequest struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Profile string `json:"profile"`
	Size    string `json:"size"`
	Width   int    `json:"width"`
}

type batchRequest struct {
	File       string             `json:"file"`
	Filename   string             `json:"filename"`
	FileName   string             `json:"file_name"`
	Version    string             `json:"version"`
	Ver        string             `json:"ver"`
	User       string             `json:"user"`
	UserID     string             `json:"user_id"`
	Purpose    string             `json:"purpose"`
	TTL        duration           `json:"ttl"`
	TTLSeconds int64              `json:"ttl_seconds"`
	Count      int                `json:"count"`
	Profiles   []string           `json:"profiles"`
	Sizes      []string           `json:"sizes"`
	Items      []batchItemRequest `json:"items"`
}

func (r batchRequest) file() string {
	return firstNonEmpty(r.File, r.Filename, r.FileName)
}

func (r batchRequest) version() string { return firstNonEmpty(r.Version, r.Ver) }
func (r batchRequest) user() string    { return firstNonEmpty(r.User, r.UserID) }

func (r batchRequest) ttl() time.Duration {
	if r.TTLSeconds > 0 {
		return time.Duration(r.TTLSeconds) * time.Second
	}
	if r.TTL > 0 {
		return time.Duration(r.TTL)
	}
	return 0
}

func (r batchRequest) itemIDs() []string {
	var ids []string
	for _, item := range r.Items {
		id := firstNonEmpty(item.ID, item.Name, item.Profile, item.Size)
		if id == "" && item.Width > 0 {
			id = "w" + strconv.Itoa(item.Width)
		}
		if id != "" {
			ids = append(ids, id)
		}
	}
	if len(ids) > 0 {
		return ids
	}
	if len(r.Profiles) > 0 {
		return append([]string(nil), r.Profiles...)
	}
	if len(r.Sizes) > 0 {
		return append([]string(nil), r.Sizes...)
	}
	if r.Count > 0 {
		for i := 1; i <= r.Count; i++ {
			ids = append(ids, "thumb-"+strconv.Itoa(i))
		}
		return ids
	}
	return nil // Manager applies its default set
}

type batchTokenResponse struct {
	Item         string       `json:"item"`
	Token        string       `json:"token"`
	URL          string       `json:"url"`
	ThumbnailURL string       `json:"thumbnail_url"`
	Claims       token.Claims `json:"claims"`
}

type batchResponse struct {
	BatchID   string               `json:"batch_id"`
	ExpiresAt time.Time            `json:"expires_at"`
	Items     []batchTokenResponse `json:"items"`
	Tokens    []string             `json:"tokens"`
	URLs      []string             `json:"urls"`
}

func (s *Server) handleIssueBatch(w http.ResponseWriter, r *http.Request) {
	var req batchRequest
	if r.ContentLength != 0 {
		if err := decodeJSON(w, r, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, errorResponse{Error: err.Error(), Reason: "bad_json"})
			return
		}
	}

	batch, err := s.mgr.IssueBatch(token.BatchRequest{
		File:    req.file(),
		Version: req.version(),
		User:    req.user(),
		Purpose: req.Purpose,
		TTL:     req.ttl(),
		Items:   req.itemIDs(),
	})
	if err != nil {
		s.writeTokenError(w, err)
		return
	}

	resp := batchResponse{BatchID: batch.BatchID, ExpiresAt: batch.ExpiresAt}
	for i, raw := range batch.Tokens {
		item := batch.Items[i]
		url := "/preview/thumbnail?token=" + raw + "&item=" + item
		resp.Items = append(resp.Items, batchTokenResponse{
			Item: item, Token: raw, URL: url, ThumbnailURL: url, Claims: batch.Claims[i],
		})
		resp.Tokens = append(resp.Tokens, raw)
		resp.URLs = append(resp.URLs, url)
	}
	writeJSON(w, http.StatusCreated, resp)
}

type sessionRequest struct {
	Token     string `json:"token"`
	PageToken string `json:"page_token"`
}

type sessionResponse struct {
	BatchToken              string    `json:"batch_token"`
	Token                   string    `json:"token"`
	TokenType               string    `json:"token_type"`
	BatchID                 string    `json:"batch_id"`
	Items                   []string  `json:"items"`
	ExpiresAt               time.Time `json:"expires_at"`
	ThumbnailURLTemplate    string    `json:"thumbnail_url_template"`
	ThumbnailURLTemplateAlt string    `json:"thumbnail_url_tpl"`
}

func (s *Server) handleSession(w http.ResponseWriter, r *http.Request) {
	var req sessionRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: err.Error(), Reason: "bad_json"})
		return
	}
	raw := firstNonEmpty(req.Token, req.PageToken)
	grant, claims, err := s.mgr.OpenSession(raw)
	if err != nil {
		s.writeTokenError(w, err)
		return
	}
	tpl := "/preview/thumbnail?batch_token=" + grant + "&item={item}"
	writeJSON(w, http.StatusCreated, sessionResponse{
		BatchToken:              grant,
		Token:                   grant,
		TokenType:               "thumbnail-batch-grant",
		BatchID:                 claims.BatchID,
		Items:                   claims.Items,
		ExpiresAt:               claims.ExpiresAt,
		ThumbnailURLTemplate:    tpl,
		ThumbnailURLTemplateAlt: tpl,
	})
}

type verifyRequest struct {
	Token      string `json:"token"`
	File       string `json:"file"`
	Filename   string `json:"filename"`
	Version    string `json:"version"`
	User       string `json:"user"`
	UserID     string `json:"user_id"`
	Purpose    string `json:"purpose"`
	Item       string `json:"item"`
	BatchToken string `json:"batch_token"`
}

func (s *Server) handleVerify(w http.ResponseWriter, r *http.Request) {
	var req verifyRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: err.Error(), Reason: "bad_json"})
		return
	}
	raw := firstNonEmpty(req.Token, req.BatchToken)
	bind := token.Binding{
		File:    firstNonEmpty(req.File, req.Filename),
		Version: req.Version,
		User:    firstNonEmpty(req.User, req.UserID),
		Purpose: req.Purpose,
		Item:    req.Item,
	}
	claims, err := s.mgr.Consume(raw, bind)
	if err != nil {
		s.writeTokenError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"valid":  true,
		"claims": claims,
	})
}

// handleValidate checks a token without consuming it.
func (s *Server) handleValidate(w http.ResponseWriter, r *http.Request) {
	var req verifyRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: err.Error(), Reason: "bad_json"})
		return
	}
	raw := firstNonEmpty(req.Token, req.BatchToken)
	bind := token.Binding{
		File:    firstNonEmpty(req.File, req.Filename),
		Version: req.Version,
		User:    firstNonEmpty(req.User, req.UserID),
		Purpose: req.Purpose,
		Item:    req.Item,
	}
	claims, err := s.mgr.Check(raw, bind)
	if err != nil {
		s.writeTokenError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"valid":    true,
		"consumed": false,
		"claims":   claims,
	})
}

func timeOrZero(t *time.Time) time.Time {
	if t == nil {
		return time.Time{}
	}
	return *t
}
