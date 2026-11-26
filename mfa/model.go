// Package mfa implements the approval-based MFA reset workflow of the
// enterprise identity management console. It replaces the legacy operation
// where an administrator could directly clear a user's MFA fields.
//
// The workflow is:
//
//  1. A user submits a reset request describing why the authenticator was
//     lost, the requested temporary recovery window, how the one-time
//     recovery credential should be delivered, and the condition that ends
//     the window.
//  2. An administrator approves or rejects the request. Approval opens the
//     recovery window and delivers a single-use recovery token through the
//     requested notification channel.
//  3. During the window the user may reach low-sensitivity applications only;
//     high-sensitivity applications stay blocked.
//  4. The window ends when it expires, when an administrator revokes it, or
//     when the user re-registers an authenticator. After the window ends the
//     user must re-register before normal access is restored.
package mfa

import "time"

// Role identifies the console role of an actor.
type Role string

const (
	RoleUser  Role = "user"
	RoleAdmin Role = "admin"
)

// RequestStatus is the lifecycle state of an MFA reset request.
type RequestStatus string

const (
	// StatusPending waits for an administrator decision.
	StatusPending RequestStatus = "pending"
	// StatusActive means the request was approved and the recovery window
	// is currently open.
	StatusActive RequestStatus = "active"
	// StatusRejected means an administrator rejected the request.
	StatusRejected RequestStatus = "rejected"
	// StatusExpired means the recovery window ended without re-registration.
	// The user must register a new authenticator before access is restored.
	StatusExpired RequestStatus = "expired"
	// StatusRevoked means an administrator ended the recovery window early.
	StatusRevoked RequestStatus = "revoked"
	// StatusReEnrolled means the user registered a new authenticator and the
	// recovery window was closed by re-registration.
	StatusReEnrolled RequestStatus = "reenrolled"
)

// Closed reports whether the request has left the active recovery state.
func (s RequestStatus) Closed() bool {
	switch s {
	case StatusExpired, StatusRevoked, StatusReEnrolled, StatusRejected:
		return true
	default:
		return false
	}
}

// NotifyMethod is the channel used to deliver the recovery token.
type NotifyMethod string

const (
	NotifyEmail NotifyMethod = "email"
	NotifySMS   NotifyMethod = "sms"
)

// Valid reports whether the notification method is supported.
func (n NotifyMethod) Valid() bool {
	return n == NotifyEmail || n == NotifySMS
}

// EndCondition declares how the applicant expects the recovery window to end.
type EndCondition string

const (
	// EndConditionWindowExpiry closes the window automatically at its expiry
	// time; the user then has to re-register an authenticator.
	EndConditionWindowExpiry EndCondition = "window_expiry"
	// EndConditionReEnrollment closes the window as soon as the user
	// re-registers an authenticator, or at expiry, whichever comes first.
	EndConditionReEnrollment EndCondition = "reenrollment"
)

// Valid reports whether the end condition is supported.
func (e EndCondition) Valid() bool {
	return e == EndConditionWindowExpiry || e == EndConditionReEnrollment
}

// MaxWindowMinutes bounds the temporary recovery window. A lost authenticator
// is a security event, so the window is deliberately short.
const MaxWindowMinutes = 120

// User is a console account. MFASecret is never serialized to clients.
type User struct {
	ID          string
	Name        string
	Role        Role
	Email       string
	Phone       string
	MFAEnrolled bool
	MFASecret   string
}

// App is an application protected by the console.
type App struct {
	ID            string
	Name          string
	HighSensitive bool
}

// ResetRequest is an MFA reset (lost authenticator) request.
type ResetRequest struct {
	ID                string
	UserID            string
	Reason            string
	NotifyMethod      NotifyMethod
	WindowMinutes     int
	EndCondition      EndCondition
	Status            RequestStatus
	CreatedAt         time.Time
	DecidedBy         string
	DecidedAt         time.Time
	DecisionNote      string
	WindowExpiresAt   time.Time
	RecoveryTokenHash string
	ReEnrolledAt      time.Time
	ClosedAt          time.Time
}

// WindowOpen reports whether the recovery window is open at time now.
func (r *ResetRequest) WindowOpen(now time.Time) bool {
	return r.Status == StatusActive && now.Before(r.WindowExpiresAt)
}

// AuditEvent records a state transition for compliance review.
type AuditEvent struct {
	Time      time.Time
	ActorID   string
	Action    string
	RequestID string
	Detail    string
}
