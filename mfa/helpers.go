package mfa

import (
	"crypto/rand"
	"errors"
	"fmt"
)

// joinError attaches a human-readable detail to a sentinel error while
// keeping errors.Is working.
func joinError(base error, detail string) error {
	return fmt.Errorf("%w: %s", base, detail)
}

// readRandom fills buf with cryptographically secure random bytes.
func readRandom(buf []byte) (int, error) {
	n, err := rand.Read(buf)
	if err != nil {
		return n, fmt.Errorf("mfa: read random bytes: %w", err)
	}
	return n, nil
}

// errorCode maps workflow errors to stable machine-readable codes used in
// JSON responses.
func errorCode(err error) string {
	switch {
	case errors.Is(err, ErrNotFound):
		return "not_found"
	case errors.Is(err, ErrUnauthorized):
		return "unauthorized"
	case errors.Is(err, ErrInvalidInput):
		return "invalid_input"
	case errors.Is(err, ErrPendingRequest):
		return "pending_request_exists"
	case errors.Is(err, ErrInvalidTransition):
		return "invalid_transition"
	case errors.Is(err, ErrWindowExpired):
		return "window_expired"
	case errors.Is(err, ErrInvalidRecoveryToken):
		return "invalid_recovery_token"
	case errors.Is(err, ErrHighSensitiveBlocked):
		return "high_sensitive_blocked"
	case errors.Is(err, ErrMFARequired):
		return "mfa_required"
	case errors.Is(err, ErrContactMissing):
		return "contact_missing"
	default:
		return "internal_error"
	}
}
