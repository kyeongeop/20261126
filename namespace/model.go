package namespace

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

const (
	SchemaVersion = 1

	RolePublisher = "publisher"
	RoleAdmin     = "admin"

	NamespaceReserved = "reserved"
	NamespaceExpired  = "expired"
	NamespaceLocked   = "locked"

	ClaimPending   = "pending"
	ClaimApproved  = "approved"
	ClaimRejected  = "rejected"
	ClaimExpired   = "expired"
	ClaimCancelled = "cancelled"

	AuditClaimCreated         = "namespace.claim.created"
	AuditClaimCancelled       = "namespace.claim.cancelled"
	AuditClaimApproved        = "namespace.claim.approved"
	AuditClaimRejected        = "namespace.claim.rejected"
	AuditClaimExpired         = "namespace.claim.expired"
	AuditReservationExpired   = "namespace.reservation.expired"
	AuditReservationRenewed   = "namespace.reservation.renewed"
	AuditOwnershipTransferred = "namespace.ownership.transferred"
	AuditPackagePublished     = "namespace.package.published"
)

var namespaceNamePattern = regexp.MustCompile(`^[a-z][a-z0-9-]{1,62}$`)
var packagePartPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
var versionPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$`)

var (
	ErrNotFound             = &Error{Code: "not_found", Status: 404, Message: "resource not found"}
	ErrUnauthorized         = &Error{Code: "unauthorized", Status: 401, Message: "valid bearer token required"}
	ErrForbidden            = &Error{Code: "forbidden", Status: 403, Message: "permission denied"}
	ErrConflict             = &Error{Code: "conflict", Status: 409, Message: "request conflicts with current state"}
	ErrValidation           = &Error{Code: "invalid_request", Status: 400, Message: "request validation failed"}
	ErrNamespaceHasPackages = &Error{
		Code:    "namespace_has_packages",
		Status:  409,
		Message: "namespace already contains packages; use an admin-created ownership transfer",
	}
	ErrNamespaceUnavailable = &Error{
		Code:    "namespace_unavailable",
		Status:  409,
		Message: "namespace is already owned or has an active claim",
	}
)

type Error struct {
	Code    string `json:"code"`
	Status  int    `json:"-"`
	Message string `json:"message"`
	Details string `json:"details,omitempty"`
}

func (e *Error) Error() string {
	if e.Details == "" {
		return e.Message
	}
	return e.Message + ": " + e.Details
}

func asError(err error) *Error {
	if err == nil {
		return nil
	}
	var apiErr *Error
	if errors.As(err, &apiErr) {
		clone := *apiErr
		return &clone
	}
	return &Error{Code: "internal_error", Status: 500, Message: "internal server error", Details: err.Error()}
}

func validationError(format string, args ...any) *Error {
	clone := *ErrValidation
	clone.Details = fmt.Sprintf(format, args...)
	return &clone
}

func conflictError(code, format string, args ...any) *Error {
	return &Error{Code: code, Status: 409, Message: "request conflicts with current state", Details: fmt.Sprintf(format, args...)}
}

type User struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Role        string `json:"role"`
	TokenSHA256 string `json:"token_sha256,omitempty"`
}

type Policy struct {
	ClaimHoldHours          int `json:"claim_hold_hours"`
	DefaultReservationDays  int `json:"default_reservation_days"`
	MaxReservationDays      int `json:"max_reservation_days"`
	MaxPendingClaimsPerUser int `json:"max_pending_claims_per_user"`
}

func defaultPolicy() Policy {
	return Policy{
		ClaimHoldHours:          72,
		DefaultReservationDays:  90,
		MaxReservationDays:      3650,
		MaxPendingClaimsPerUser: 3,
	}
}

func (p Policy) normalized() Policy {
	fallback := defaultPolicy()
	if p.ClaimHoldHours <= 0 {
		p.ClaimHoldHours = fallback.ClaimHoldHours
	}
	if p.DefaultReservationDays <= 0 {
		p.DefaultReservationDays = fallback.DefaultReservationDays
	}
	if p.MaxReservationDays < p.DefaultReservationDays {
		p.MaxReservationDays = fallback.MaxReservationDays
	}
	if p.MaxPendingClaimsPerUser <= 0 {
		p.MaxPendingClaimsPerUser = fallback.MaxPendingClaimsPerUser
	}
	return p
}

type Namespace struct {
	Name          string    `json:"name"`
	State         string    `json:"state"`
	OwnerID       string    `json:"owner_id,omitempty"`
	OwnerName     string    `json:"owner_name,omitempty"`
	ReservedUntil time.Time `json:"reserved_until,omitempty"`
	ClaimID       string    `json:"claim_id,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

type Claim struct {
	ID            string    `json:"id"`
	Namespace     string    `json:"namespace"`
	ClaimantID    string    `json:"claimant_id"`
	ClaimantName  string    `json:"claimant_name"`
	Reason        string    `json:"reason"`
	Status        string    `json:"status"`
	RequestedDays int       `json:"requested_reservation_days,omitempty"`
	HoldUntil     time.Time `json:"hold_until"`
	CreatedAt     time.Time `json:"created_at"`
	DecidedAt     time.Time `json:"decided_at,omitempty"`
	DecidedBy     string    `json:"decided_by,omitempty"`
	DecisionNote  string    `json:"decision_note,omitempty"`
	ReservedUntil time.Time `json:"reserved_until,omitempty"`
}

type Package struct {
	Namespace   string    `json:"namespace"`
	Name        string    `json:"name"`
	Version     string    `json:"version"`
	PublishedBy string    `json:"published_by"`
	PublishedAt time.Time `json:"published_at"`
}

type AuditEvent struct {
	Sequence      int64     `json:"sequence"`
	ID            string    `json:"id"`
	Type          string    `json:"type"`
	Namespace     string    `json:"namespace,omitempty"`
	ActorID       string    `json:"actor_id"`
	ActorName     string    `json:"actor_name"`
	ActorRole     string    `json:"actor_role"`
	RequestID     string    `json:"request_id,omitempty"`
	RemoteAddr    string    `json:"remote_addr,omitempty"`
	ClaimID       string    `json:"claim_id,omitempty"`
	FromOwnerID   string    `json:"from_owner_id,omitempty"`
	FromOwnerName string    `json:"from_owner_name,omitempty"`
	ToOwnerID     string    `json:"to_owner_id,omitempty"`
	ToOwnerName   string    `json:"to_owner_name,omitempty"`
	Reason        string    `json:"reason,omitempty"`
	Details       string    `json:"details,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
	PreviousHash  string    `json:"previous_hash"`
	Hash          string    `json:"hash"`
}

type State struct {
	SchemaVersion int                  `json:"schema_version"`
	Policy        Policy               `json:"policy"`
	Users         []User               `json:"users"`
	Namespaces    map[string]Namespace `json:"namespaces"`
	Claims        []Claim              `json:"claims"`
	Packages      map[string][]Package `json:"packages"`
	Audit         []AuditEvent         `json:"audit"`
}

func validateNamespaceName(name string) error {
	name = strings.TrimSpace(name)
	if !namespaceNamePattern.MatchString(name) {
		return validationError("namespace must match %s", namespaceNamePattern.String())
	}
	if strings.Contains(name, "--") {
		return validationError("namespace cannot contain consecutive hyphens")
	}
	return nil
}

func validatePackagePart(name string) error {
	if !packagePartPattern.MatchString(name) || strings.Contains(name, "..") {
		return validationError("package name is invalid")
	}
	return nil
}

func validateVersion(version string) error {
	if !versionPattern.MatchString(version) || strings.Contains(version, "..") {
		return validationError("package version is invalid")
	}
	return nil
}
