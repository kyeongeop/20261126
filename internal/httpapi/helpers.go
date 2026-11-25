package httpapi

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
)

// decodeBody reads a JSON request body with a size cap and rejects unknown
// fields so typos surface as 400 instead of being silently dropped.
func decodeBody(r *http.Request, dst any) error {
	if r.Body == nil {
		return errors.New("request body is required")
	}
	defer r.Body.Close()
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("request body must contain a single JSON object")
	}
	return nil
}
