package source

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// HTTPSource fetches packages over HTTP(S) using Range requests so an
// interrupted transfer can resume at the last received byte.
type HTTPSource struct {
	BaseURL string
	Client  *http.Client
}

// NewHTTPSource normalizes the base URL and ensures it ends with a slash.
func NewHTTPSource(baseURL string) (*HTTPSource, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid source URL %q: %w", baseURL, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("source URL must use http or https: %q", baseURL)
	}
	if !strings.HasSuffix(u.Path, "/") {
		u.Path += "/"
	}
	return &HTTPSource{BaseURL: u.String(), Client: http.DefaultClient}, nil
}

func (h *HTTPSource) packageURL(path string) string {
	u, err := url.Parse(h.BaseURL)
	if err != nil {
		return h.BaseURL + path
	}
	return u.JoinPath(path).String()
}

// Open issues a Range request starting at offset. A server that ignores the
// Range header returns the full body, which the caller handles by restarting
// the destination file from offset zero.
func (h *HTTPSource) Open(ctx context.Context, path string, offset int64) (ReadCloserAt, int64, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, h.packageURL(path), nil)
	if err != nil {
		return nil, 0, err
	}
	if offset > 0 {
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-", offset))
	}
	resp, err := h.Client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	switch {
	case resp.StatusCode == http.StatusNotFound:
		resp.Body.Close()
		return nil, 0, fmt.Errorf("%w: %s", ErrNotFound, path)
	case offset > 0 && resp.StatusCode == http.StatusPartialContent:
		total := parseContentRangeTotal(resp.Header.Get("Content-Range"))
		if total <= 0 {
			resp.Body.Close()
			return nil, 0, fmt.Errorf("server returned 206 without a valid Content-Range for %s", path)
		}
		return &httpBody{body: resp.Body, honored: true}, total, nil
	case resp.StatusCode == http.StatusOK:
		total := resp.ContentLength
		return &httpBody{body: resp.Body, honored: false}, total, nil
	default:
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		return nil, 0, fmt.Errorf("GET %s failed: status %d: %s", path, resp.StatusCode, strings.TrimSpace(string(body)))
	}
}

type httpBody struct {
	body    io.ReadCloser
	honored bool
}

func (r *httpBody) Read(p []byte) (int, error) { return r.body.Read(p) }
func (r *httpBody) Close() error               { return r.body.Close() }
func (r *httpBody) HonoredOffset() bool        { return r.honored }

// parseContentRangeTotal extracts the total size from "bytes start-end/total".
func parseContentRangeTotal(header string) int64 {
	idx := strings.LastIndex(header, "/")
	if idx < 0 {
		return 0
	}
	total, err := strconv.ParseInt(header[idx+1:], 10, 64)
	if err != nil || total < 0 {
		return 0
	}
	return total
}
