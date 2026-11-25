package server

import (
	"hash/fnv"
	"image"
	"image/color"
	"image/png"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"previewtoken/token"
)

// handlePreview is the real file preview endpoint. The token must be a
// one-time preview token; every request is consumed exactly once.
func (s *Server) handlePreview(w http.ResponseWriter, r *http.Request) {
	raw := tokenFromRequest(r)
	bind := bindingFromRequest(r)
	bind.Purpose = token.PurposePreview
	s.servePreview(w, r, raw, bind)
}

// handleFilePathPreview parses
// /files/<file/path...>/versions/<version>/preview because the file name may
// itself contain slashes and cannot be a single mux wildcard segment.
func (s *Server) handleFilePathPreview(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/files/")
	idx := strings.LastIndex(rest, "/versions/")
	if idx <= 0 {
		http.NotFound(w, r)
		return
	}
	file := rest[:idx]
	tail := rest[idx+len("/versions/"):]
	slash := strings.IndexByte(tail, '/')
	if slash < 0 {
		http.NotFound(w, r)
		return
	}
	version := tail[:slash]
	action := tail[slash+1:]
	if action != "preview" || file == "" || version == "" {
		http.NotFound(w, r)
		return
	}

	q := r.URL.Query()
	bind := token.Binding{
		File:    file,
		Version: version,
		User: firstNonEmpty(
			r.Header.Get("X-User-ID"),
			q.Get("user"), q.Get("user_id"),
		),
		Purpose: token.PurposePreview,
	}
	s.servePreview(w, r, tokenFromRequest(r), bind)
}

func (s *Server) servePreview(w http.ResponseWriter, r *http.Request, raw string, bind token.Binding) {
	if raw == "" {
		writeJSON(w, http.StatusUnauthorized, errorResponse{Error: "missing preview token", Reason: "invalid_token"})
		return
	}

	claims, err := s.mgr.Consume(raw, bind)
	if err != nil {
		s.writeTokenError(w, err)
		return
	}

	w.Header().Set("Cache-Control", "private, no-store, max-age=0")
	w.Header().Set("X-Content-Type-Options", "nosniff")

	if path, ok := s.contentPath(claims.File, claims.Version); ok {
		data, err := os.ReadFile(path)
		if err == nil {
			w.Header().Set("Content-Type", http.DetectContentType(data))
			w.Header().Set("Content-Disposition", "inline; filename*=UTF-8''"+urlEscape(claims.File))
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(data)
			return
		}
	}

	// No binary registered for this demo file: return an authorized JSON
	// receipt so API flows can assert successful consumption.
	writeJSON(w, http.StatusOK, map[string]any{
		"preview": true,
		"file":    claims.File,
		"version": claims.Version,
		"user":    claims.User,
		"purpose": claims.Purpose,
		"jti":     claims.JTI,
	})
}

// handleThumbnail serves one thumbnail. It accepts either a distinct
// single-use thumbnail token (batch issuance) or a short-lived KindBatch
// grant together with ?item=<id>. Distinct page requests therefore succeed
// concurrently while genuine replays are rejected.
func (s *Server) handleThumbnail(w http.ResponseWriter, r *http.Request) {
	raw := tokenFromRequest(r)
	bind := bindingFromRequest(r)
	bind.Purpose = token.PurposeThumbnail

	claims, err := s.mgr.Consume(raw, bind)
	if err != nil {
		s.writeTokenError(w, err)
		return
	}

	item := bind.Item
	if item == "" {
		item = claims.Item
	}

	w.Header().Set("Cache-Control", "private, no-store, max-age=0")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Type", "image/png")
	w.WriteHeader(http.StatusOK)
	_ = png.Encode(w, thumbnailImage(claims.File, claims.Version, item))
}

// contentPath resolves <contentDir>/<file>/versions/<version> while refusing
// path traversal outside contentDir.
func (s *Server) contentPath(file, version string) (string, bool) {
	if s.contentDir == "" || file == "" || version == "" {
		return "", false
	}
	root, err := filepath.Abs(s.contentDir)
	if err != nil {
		return "", false
	}
	clean := filepath.Clean(filepath.Join(root, file, "versions", version))
	if clean != root && !isWithin(root, clean) {
		return "", false
	}
	info, err := os.Stat(clean)
	if err != nil || info.IsDir() {
		return "", false
	}
	return clean, true
}

func isWithin(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return false
	}
	return rel != ".." && len(rel) >= 2 && rel[:2] != ".."+string(filepath.Separator)
}

// thumbnailImage renders a small deterministic placeholder PNG so batch
// <img> requests receive real image bytes without external assets.
func thumbnailImage(file, version, item string) image.Image {
	const w, h = 160, 100
	img := image.NewRGBA(image.Rect(0, 0, w, h))

	hf := fnv.New32a()
	_, _ = hf.Write([]byte(file + "|" + version + "|" + item))
	seed := hf.Sum32()
	base := color.RGBA{
		R: 80 + byte(seed%120),
		G: 90 + byte((seed>>8)%120),
		B: 140 + byte((seed>>16)%100),
		A: 255,
	}
	accent := color.RGBA{R: 240, G: 244, B: 255, A: 255}

	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			c := base
			// Diagonal stripe pattern keyed by the item id.
			if (x+y+int(seed%17))%24 < 6 {
				c = accent
			}
			// Simple frame.
			if x < 4 || y < 4 || x >= w-4 || y >= h-4 {
				c = color.RGBA{R: 28, G: 32, B: 48, A: 255}
			}
			img.Set(x, y, c)
		}
	}

	// A pair of "mountain" blocks gives the thumbnail a recognizable shape.
	for y := 55; y < 86; y++ {
		for x := 18; x < 70; x++ {
			if (y-55)*2 > (x - 18) {
				img.Set(x, y, color.RGBA{R: 220, G: 230, B: 250, A: 255})
			}
		}
		for x := 80; x < 142; x++ {
			if (y-55)*2 > (142 - x) {
				img.Set(x, y, color.RGBA{R: 190, G: 210, B: 245, A: 255})
			}
		}
	}
	_ = accent
	return img
}

// urlEscape minimally percent-escapes a filename for Content-Disposition.
func urlEscape(s string) string {
	const hex = "0123456789ABCDEF"
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9',
			c == '-', c == '_', c == '.', c == '~':
			out = append(out, c)
		default:
			out = append(out, '%', hex[c>>4], hex[c&0x0f])
		}
	}
	return string(out)
}
