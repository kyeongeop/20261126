package revoke

import (
	"crypto/x509"
	"fmt"
	"time"
)

// Verifier applies a Source plus a staleness policy to client certificates.
type Verifier struct {
	Source      *Source
	StalePolicy StalePolicy
	Now         func() time.Time // optional; defaults to time.Now
}

func (v *Verifier) now() time.Time {
	if v.Now != nil {
		return v.Now()
	}
	return time.Now()
}

// Check evaluates cert and returns the decision with an audit-ready reason.
func (v *Verifier) Check(cert *x509.Certificate) Decision {
	res := v.Source.Lookup(cert.SerialNumber, v.now())
	d := Decision{Result: res}
	switch res.Status {
	case StatusRevoked:
		d.Reason = fmt.Sprintf("certificate revoked according to pinned %s (thisUpdate=%s)",
			res.Source, res.ThisUpdate.UTC().Format(time.RFC3339))
		return d
	case StatusUnknown:
		if res.Source == "none" {
			d.Reason = "no pinned CRL or OCSP response covers this issuer"
		} else {
			d.Reason = fmt.Sprintf("pinned %s reports status unknown", res.Source)
		}
		return d
	}
	// StatusGood from here on.
	if res.Stale {
		staleNote := fmt.Sprintf("pinned %s response stale (nextUpdate=%s expired)",
			res.Source, res.NextUpdate.UTC().Format(time.RFC3339))
		switch v.StalePolicy {
		case StaleAllow:
			d.Allowed = true
			d.Reason = staleNote + "; stale-policy=allow, connection accepted"
		case StaleDegrade:
			d.Allowed = true
			d.Degraded = true
			d.Reason = staleNote + "; stale-policy=degrade, connection accepted in degraded mode"
		default:
			d.Reason = staleNote + "; stale-policy=deny, connection rejected"
		}
		return d
	}
	d.Allowed = true
	d.Reason = fmt.Sprintf("certificate good per pinned %s (thisUpdate=%s nextUpdate=%s)",
		res.Source,
		res.ThisUpdate.UTC().Format(time.RFC3339),
		res.NextUpdate.UTC().Format(time.RFC3339))
	return d
}
