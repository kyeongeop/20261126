package guest

import "fmt"

// Error is an error with a stable API code and HTTP status.
type Error struct {
	Code       string
	Message    string
	HTTPStatus int
	Err        error
}

func (e *Error) Error() string {
	if e.Err == nil {
		return e.Message
	}
	return fmt.Sprintf("%s: %v", e.Message, e.Err)
}

func (e *Error) Unwrap() error {
	return e.Err
}

func newError(code, message string, status int) *Error {
	return &Error{Code: code, Message: message, HTTPStatus: status}
}

func wrapError(code, message string, status int, err error) *Error {
	return &Error{Code: code, Message: message, HTTPStatus: status, Err: err}
}

var (
	ErrUnauthorized       = newError("unauthorized", "authentication is required", 401)
	ErrInvitationNotFound = newError("invitation_not_found", "invitation was not found", 404)
	ErrInvitationInvalid  = newError("invitation_invalid", "invitation token is invalid", 401)
	ErrInvitationExpired  = newError("invitation_expired", "invitation has expired", 401)
	ErrInvitationRevoked  = newError("invitation_revoked", "invitation has been revoked", 401)
	ErrPasscodeRequired   = newError("passcode_required", "a passcode is required", 401)
	ErrPasscodeInvalid    = newError("passcode_invalid", "passcode is invalid", 401)
	ErrSessionInvalid     = newError("session_invalid", "guest session is invalid", 401)
	ErrDirectoryMissing   = newError("directory_unavailable", "authorized directory is no longer available", 410)
	ErrPathOutsideRoot    = newError("path_outside_authorized_directory", "path is outside the authorized directory", 403)
	ErrFileNotFound       = newError("file_not_found", "file or directory was not found", 404)
	ErrNotAFile           = newError("not_a_file", "requested path is a directory", 400)
)
