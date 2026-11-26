package main

import "errors"

var (
	errNotFound        = errors.New("resource not found")
	errPackageNotFound = errors.New("package not found")
	errVersionNotFound = errors.New("package version not found")
	errRequestNotFound = errors.New("deletion request not found")

	errInvalidName    = errors.New("invalid package name")
	errInvalidVersion = errors.New("invalid package version")
	errInvalidInput   = errors.New("invalid input")
	errInvalidTar     = errors.New("artifact is not a valid tar archive")
	errDigestMismatch = errors.New("artifact sha256 digest does not match")

	errAlreadyPublished  = errors.New("package name and version already published")
	errAlreadyPending    = errors.New("an active deletion request already exists for this target")
	errNotDue            = errors.New("cooldown period has not elapsed")
	errReferenced        = errors.New("package is referenced by other active packages")
	errSameConfirmer     = errors.New("confirmation must come from a different privileged account")
	errInvalidTransition = errors.New("deletion request cannot perform this action in its current state")
	errForbidden         = errors.New("forbidden")
	errUnauthorized      = errors.New("authentication required")
)

// errorCode 把领域错误映射为稳定的机器可读错误码。
func errorCode(err error) string {
	switch {
	case errors.Is(err, errPackageNotFound), errors.Is(err, errVersionNotFound),
		errors.Is(err, errRequestNotFound), errors.Is(err, errNotFound):
		return "not_found"
	case errors.Is(err, errInvalidName):
		return "invalid_package_name"
	case errors.Is(err, errInvalidVersion):
		return "invalid_version"
	case errors.Is(err, errInvalidTar):
		return "invalid_tar"
	case errors.Is(err, errDigestMismatch):
		return "digest_mismatch"
	case errors.Is(err, errAlreadyPublished):
		return "version_exists"
	case errors.Is(err, errAlreadyPending):
		return "deletion_already_pending"
	case errors.Is(err, errNotDue):
		return "cooldown_not_elapsed"
	case errors.Is(err, errReferenced):
		return "package_referenced"
	case errors.Is(err, errSameConfirmer):
		return "different_confirmer_required"
	case errors.Is(err, errInvalidTransition):
		return "invalid_state_transition"
	case errors.Is(err, errForbidden):
		return "forbidden"
	case errors.Is(err, errUnauthorized):
		return "unauthorized"
	default:
		return "internal_error"
	}
}
