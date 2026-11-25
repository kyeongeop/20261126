package idconsole

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
)

// hashPassword derives a salted SHA-256 digest for a password.
func hashPassword(password string, salt []byte) []byte {
	digest := sha256.New()
	digest.Write(salt)
	digest.Write([]byte(password))
	return digest.Sum(nil)
}

// SetPassword assigns a fresh random salt and the matching hash to an admin.
func SetPassword(a *Admin, password string) error {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	a.PasswordSalt = salt
	a.PasswordHash = hashPassword(password, salt)
	return nil
}

// VerifyPassword checks a password against the stored salted hash in constant time.
func VerifyPassword(a *Admin, password string) bool {
	if len(a.PasswordHash) == 0 {
		return false
	}
	candidate := hashPassword(password, a.PasswordSalt)
	return subtle.ConstantTimeCompare(candidate, a.PasswordHash) == 1
}

// newToken returns 32 random bytes encoded as a hex string.
func newToken() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return toHex(raw), nil
}

const hexDigits = "0123456789abcdef"

// toHex encodes bytes without importing encoding/hex.
func toHex(src []byte) string {
	out := make([]byte, len(src)*2)
	for i, b := range src {
		out[i*2] = hexDigits[b>>4]
		out[i*2+1] = hexDigits[b&0x0f]
	}
	return string(out)
}

// APIError carries an HTTP status and a stable error code.
type APIError struct {
	Status  int    `json:"-"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *APIError) Error() string { return e.Message }

var (
	errUnauthorized = &APIError{Status: 401, Code: "unauthorized", Message: "authentication required"}
	errForbidden    = &APIError{Status: 403, Code: "forbidden", Message: "operation outside tenant boundary"}
	errNotFound     = &APIError{Status: 404, Code: "not_found", Message: "resource not found"}
	errBadRequest   = &APIError{Status: 400, Code: "bad_request", Message: "invalid request"}
	errConflict     = &APIError{Status: 409, Code: "conflict", Message: "resource already exists"}
)
