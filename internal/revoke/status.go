package revoke

import "time"

// Status is the revocation state of a certificate.
type Status int

const (
	StatusGood Status = iota
	StatusRevoked
	StatusUnknown
)

func (s Status) String() string {
	switch s {
	case StatusGood:
		return "good"
	case StatusRevoked:
		return "revoked"
	default:
		return "unknown"
	}
}

// StalePolicy decides what happens when a pinned CRL or OCSP response
// is past its NextUpdate time.
type StalePolicy int

const (
	// StaleDeny rejects the connection (fail-closed).
	StaleDeny StalePolicy = iota
	// StaleAllow accepts the connection (fail-open).
	StaleAllow
	// StaleDegrade accepts the connection but marks it degraded.
	StaleDegrade
)

func ParseStalePolicy(s string) (StalePolicy, error) {
	switch s {
	case "deny":
		return StaleDeny, nil
	case "allow":
		return StaleAllow, nil
	case "degrade":
		return StaleDegrade, nil
	default:
		return StaleDeny, &Error{Msg: "unknown stale policy: " + s}
	}
}

func (p StalePolicy) String() string {
	switch p {
	case StaleAllow:
		return "allow"
	case StaleDegrade:
		return "degrade"
	default:
		return "deny"
	}
}

// Error is a configuration or parsing error in this package.
type Error struct{ Msg string }

func (e *Error) Error() string { return e.Msg }

// Result is the outcome of a revocation lookup.
type Result struct {
	Status     Status
	Source     string // "crl", "ocsp" or "none"
	ThisUpdate time.Time
	NextUpdate time.Time
	Stale      bool
}

// Decision is the final allow/deny/degrade verdict for a connection.
type Decision struct {
	Allowed  bool
	Degraded bool
	Result   Result
	Reason   string
}
