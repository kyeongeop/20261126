package roleadmin

import (
	"errors"
	"fmt"
	"net/http"
)

type APIError struct {
	Status  int
	Code    string
	Message string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

func invalid(code, format string, args ...any) error {
	return &APIError{
		Status:  http.StatusUnprocessableEntity,
		Code:    code,
		Message: fmt.Sprintf(format, args...),
	}
}

func badRequest(code, format string, args ...any) error {
	return &APIError{
		Status:  http.StatusBadRequest,
		Code:    code,
		Message: fmt.Sprintf(format, args...),
	}
}

func notFound(format string, args ...any) error {
	return &APIError{
		Status:  http.StatusNotFound,
		Code:    "not_found",
		Message: fmt.Sprintf(format, args...),
	}
}

func conflict(code, format string, args ...any) error {
	return &APIError{
		Status:  http.StatusConflict,
		Code:    code,
		Message: fmt.Sprintf(format, args...),
	}
}

func forbidden(code, format string, args ...any) error {
	return &APIError{
		Status:  http.StatusForbidden,
		Code:    code,
		Message: fmt.Sprintf(format, args...),
	}
}

func unauthorized(code, format string, args ...any) error {
	return &APIError{
		Status:  http.StatusUnauthorized,
		Code:    code,
		Message: fmt.Sprintf(format, args...),
	}
}

func asAPIError(err error) *APIError {
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return apiErr
	}
	return &APIError{
		Status:  http.StatusInternalServerError,
		Code:    "internal_error",
		Message: "internal server error",
	}
}
