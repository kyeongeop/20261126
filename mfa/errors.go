package mfa

import "errors"

// Sentinel errors returned by the workflow. The HTTP layer maps them to
// status codes; callers may inspect them with errors.Is.
var (
	ErrNotFound             = errors.New("mfa: resource not found")
	ErrInvalidInput         = errors.New("mfa: invalid request input")
	ErrUnauthorized         = errors.New("mfa: actor not authorized")
	ErrPendingRequest       = errors.New("mfa: an active or pending reset request already exists")
	ErrInvalidTransition    = errors.New("mfa: request is not in a state that allows this action")
	ErrWindowExpired        = errors.New("mfa: recovery window has ended; re-registration required")
	ErrInvalidRecoveryToken = errors.New("mfa: invalid or already consumed recovery token")
	ErrHighSensitiveBlocked = errors.New("mfa: high-sensitivity applications are blocked during recovery")
	ErrMFARequired          = errors.New("mfa: MFA verification required for this application")
	ErrContactMissing       = errors.New("mfa: user has no contact address for the requested notification method")
)
