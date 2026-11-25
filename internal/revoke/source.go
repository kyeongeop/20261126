package revoke

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"
)

// Source holds pinned, offline revocation material for one or more issuers.
type Source struct {
	CRLs  []*x509.RevocationList
	OCSPs []*PinnedOCSP
}

// LoadCRLFile reads a PEM- or DER-encoded CRL and verifies it against issuer.
func (s *Source) LoadCRLFile(path string, issuer *x509.Certificate) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if block, _ := pem.Decode(data); block != nil {
		data = block.Bytes
	}
	crl, err := x509.ParseRevocationList(data)
	if err != nil {
		return fmt.Errorf("parse CRL %s: %w", path, err)
	}
	if err := crl.CheckSignatureFrom(issuer); err != nil {
		return fmt.Errorf("CRL %s: %w", path, err)
	}
	s.CRLs = append(s.CRLs, crl)
	return nil
}

// LoadOCSPFile reads a DER (or PEM-wrapped) OCSP response pinned for issuer.
func (s *Source) LoadOCSPFile(path string, issuer *x509.Certificate) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if block, _ := pem.Decode(data); block != nil {
		data = block.Bytes
	}
	pinned, err := ParseOCSPResponse(data, issuer)
	if err != nil {
		return fmt.Errorf("OCSP %s: %w", path, err)
	}
	s.OCSPs = append(s.OCSPs, pinned)
	return nil
}

// Lookup returns the revocation status of serial. Pinned OCSP responses take
// precedence over CRLs. now decides staleness against NextUpdate.
func (s *Source) Lookup(serial *big.Int, now time.Time) Result {
	for _, pinned := range s.OCSPs {
		if single, ok := pinned.lookup(serial); ok {
			return Result{
				Status:     single.Status,
				Source:     "ocsp",
				ThisUpdate: single.ThisUpdate,
				NextUpdate: single.NextUpdate,
				Stale:      stale(single.NextUpdate, now),
			}
		}
	}
	for _, crl := range s.CRLs {
		res := Result{
			Status:     StatusGood,
			Source:     "crl",
			ThisUpdate: crl.ThisUpdate,
			NextUpdate: crl.NextUpdate,
			Stale:      stale(crl.NextUpdate, now),
		}
		for _, entry := range crl.RevokedCertificateEntries {
			if entry.SerialNumber.Cmp(serial) == 0 {
				res.Status = StatusRevoked
				break
			}
		}
		return res
	}
	return Result{Status: StatusUnknown, Source: "none"}
}

func stale(nextUpdate, now time.Time) bool {
	return !nextUpdate.IsZero() && now.After(nextUpdate)
}
