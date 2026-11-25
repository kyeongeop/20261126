package revoke

import (
	"crypto/x509"
	"encoding/json"
	"io"
	"sync"
	"time"
)

// AuditEntry is one structured audit log record for a revocation decision.
type AuditEntry struct {
	Time       time.Time `json:"time"`
	Peer       string    `json:"peer,omitempty"`
	Subject    string    `json:"subject"`
	Serial     string    `json:"serial"`
	Source     string    `json:"source"`
	Status     string    `json:"status"`
	ThisUpdate string    `json:"this_update,omitempty"`
	NextUpdate string    `json:"next_update,omitempty"`
	Stale      bool      `json:"stale"`
	Policy     string    `json:"stale_policy"`
	Decision   string    `json:"decision"`
	Reason     string    `json:"reason"`
}

// AuditLogger writes JSON-lines audit records, safe for concurrent use.
type AuditLogger struct {
	mu  sync.Mutex
	enc *json.Encoder
}

func NewAuditLogger(w io.Writer) *AuditLogger {
	return &AuditLogger{enc: json.NewEncoder(w)}
}

// Log records the decision for cert, including the policy reason.
func (l *AuditLogger) Log(peer string, cert *x509.Certificate, d Decision, policy StalePolicy) {
	entry := AuditEntry{
		Time:   time.Now().UTC(),
		Peer:   peer,
		Stale:  d.Result.Stale,
		Policy: policy.String(),
		Reason: d.Reason,
	}
	if cert != nil {
		entry.Subject = cert.Subject.String()
		entry.Serial = cert.SerialNumber.Text(16)
	}
	entry.Source = d.Result.Source
	entry.Status = d.Result.Status.String()
	if !d.Result.ThisUpdate.IsZero() {
		entry.ThisUpdate = d.Result.ThisUpdate.UTC().Format(time.RFC3339)
	}
	if !d.Result.NextUpdate.IsZero() {
		entry.NextUpdate = d.Result.NextUpdate.UTC().Format(time.RFC3339)
	}
	switch {
	case !d.Allowed:
		entry.Decision = "deny"
	case d.Degraded:
		entry.Decision = "degrade"
	default:
		entry.Decision = "allow"
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	_ = l.enc.Encode(entry)
}
