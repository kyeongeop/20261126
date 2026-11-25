// Package identity defines the service/purpose binding embedded into client
// certificates and verified by the TLS gateway.
package identity

import (
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"

	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
)

// URIScheme is the URI SAN scheme carrying the same binding as OIDBinding.
const URIScheme = "certgw"

// OIDBinding is a private-enterprise extension OID used for the ASN.1
// Binding extension. It is intentionally non-critical: Go's chain verifier
// rejects unknown critical extensions, while the gateway always requires and
// validates this extension itself.
var OIDBinding = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 59888, 1, 1}

// Supported purposes. An invitation binds exactly one purpose and the gateway
// authorizes routes against it.
const (
	PurposeAPI     = "api"
	PurposeMetrics = "metrics"
	PurposeAdmin   = "admin"
)

// Purposes is the registry of purposes an invitation may bind.
var Purposes = []string{PurposeAPI, PurposeMetrics, PurposeAdmin}

// Binding is the signed assertion carried by every issued client certificate.
type Binding struct {
	Service      string `asn1:"utf8"`
	Purpose      string `asn1:"utf8"`
	InvitationID string `asn1:"utf8"`
}

var (
	// ErrNoBinding means the certificate does not carry a valid binding.
	ErrNoBinding = errors.New("identity: certificate has no service binding")
	// ErrBindingMismatch means the certificate is bound to another service/purpose.
	ErrBindingMismatch = errors.New("identity: certificate binding does not match target service")
)

// ValidPurpose reports whether p is a registered purpose.
func ValidPurpose(p string) bool {
	return slices.Contains(Purposes, p)
}

// Validate checks that all binding fields are present and well formed.
func (b Binding) Validate() error {
	if strings.TrimSpace(b.Service) == "" {
		return errors.New("identity: binding service is required")
	}
	if !ValidPurpose(b.Purpose) {
		return fmt.Errorf("identity: invalid purpose %q", b.Purpose)
	}
	if strings.TrimSpace(b.InvitationID) == "" {
		return errors.New("identity: binding invitation id is required")
	}
	return nil
}

// Extension returns the non-critical x509 extension holding DER(b).
func (b Binding) Extension() (pkix.Extension, error) {
	if err := b.Validate(); err != nil {
		return pkix.Extension{}, err
	}
	raw, err := asn1.Marshal(b)
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("identity: marshal binding: %w", err)
	}
	return pkix.Extension{Id: OIDBinding, Critical: false, Value: raw}, nil
}

// URI renders the standards-based SAN form of the binding:
// certgw://<service>/<purpose>/<invitation-id>.
func (b Binding) URI() (*url.URL, error) {
	if err := b.Validate(); err != nil {
		return nil, err
	}
	return &url.URL{
		Scheme: URIScheme,
		Host:   b.Service,
		Path:   "/" + b.Purpose + "/" + b.InvitationID,
	}, nil
}

// ParseURI parses a certgw:// SAN into a Binding.
func ParseURI(u *url.URL) (Binding, error) {
	if u == nil || u.Scheme != URIScheme || u.Host == "" {
		return Binding{}, ErrNoBinding
	}
	parts := strings.Split(strings.TrimPrefix(u.Path, "/"), "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return Binding{}, fmt.Errorf("%w: malformed binding URI %q", ErrNoBinding, u.String())
	}
	return Binding{Service: u.Host, Purpose: parts[0], InvitationID: parts[1]}, nil
}

// FromCertificate extracts and cross-validates the binding extension and the
// matching URI SAN from an issued certificate.
func FromCertificate(cert *x509.Certificate) (Binding, error) {
	if cert == nil {
		return Binding{}, ErrNoBinding
	}
	var b Binding
	found := false
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(OIDBinding) {
			if _, err := asn1.Unmarshal(ext.Value, &b); err != nil {
				return Binding{}, fmt.Errorf("%w: malformed extension: %v", ErrNoBinding, err)
			}
			found = true
			break
		}
	}
	if !found {
		return Binding{}, ErrNoBinding
	}
	if err := b.Validate(); err != nil {
		return Binding{}, fmt.Errorf("%w: %v", ErrNoBinding, err)
	}

	sanMatched := false
	for _, u := range cert.URIs {
		san, err := ParseURI(u)
		if err != nil {
			continue
		}
		if san == b {
			sanMatched = true
			break
		}
	}
	if !sanMatched {
		return Binding{}, fmt.Errorf("%w: URI SAN does not match extension", ErrNoBinding)
	}
	return b, nil
}

// Check extracts the certificate binding and requires Service to equal service.
// When purpose is non-empty it must also equal the bound purpose.
func Check(cert *x509.Certificate, service, purpose string) (Binding, error) {
	b, err := FromCertificate(cert)
	if err != nil {
		return Binding{}, err
	}
	if b.Service != service {
		return b, fmt.Errorf("%w: certificate is for %q, gateway is %q",
			ErrBindingMismatch, b.Service, service)
	}
	if purpose != "" && b.Purpose != purpose {
		return b, fmt.Errorf("%w: certificate purpose %q, required %q",
			ErrBindingMismatch, b.Purpose, purpose)
	}
	return b, nil
}
