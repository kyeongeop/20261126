// Package pki owns the local certificate authority and issues service-bound
// client and server certificates with crypto/x509.
package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"time"

	"certgateway/identity"
)

// DefaultCAValidity is the lifetime of an ephemeral/local root CA.
const DefaultCAValidity = 5 * 365 * 24 * time.Hour

// CA is a local signing certificate and its private key.
type CA struct {
	Cert    *x509.Certificate
	Key     *ecdsa.PrivateKey
	CertPEM []byte
	KeyPEM  []byte
}

// NewRootCA generates a self-signed ECDSA P-256 root CA.
func NewRootCA(commonName string, validity time.Duration) (*CA, error) {
	if commonName == "" {
		commonName = "certgateway-local-ca"
	}
	if validity <= 0 {
		validity = DefaultCAValidity
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("pki: generate CA key: %w", err)
	}
	serial, err := RandomSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName, Organization: []string{"certgateway"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(validity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("pki: create CA certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("pki: parse CA certificate: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("pki: marshal CA key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return &CA{Cert: cert, Key: key, CertPEM: certPEM, KeyPEM: keyPEM}, nil
}

// SignClientCSR signs a validated certificate request and binds the resulting
// certificate to exactly one service/purpose via identity.Binding.
func (a *CA) SignClientCSR(csr *x509.CertificateRequest, b identity.Binding, serial *big.Int, validity time.Duration, now time.Time) ([]byte, *x509.Certificate, error) {
	if a == nil || a.Cert == nil || a.Key == nil {
		return nil, nil, errors.New("pki: nil CA")
	}
	if csr == nil {
		return nil, nil, errors.New("pki: nil CSR")
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, nil, fmt.Errorf("pki: CSR signature invalid: %w", err)
	}
	if err := b.Validate(); err != nil {
		return nil, nil, err
	}
	if validity <= 0 {
		return nil, nil, errors.New("pki: client certificate validity must be positive")
	}
	if now.IsZero() {
		now = time.Now()
	}

	if serial == nil {
		var err error
		serial, err = RandomSerial()
		if err != nil {
			return nil, nil, err
		}
	}
	ext, err := b.Extension()
	if err != nil {
		return nil, nil, err
	}
	uri, err := b.URI()
	if err != nil {
		return nil, nil, err
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "client:" + b.InvitationID,
			Organization: []string{"certgateway-clients"},
		},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(validity),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		URIs:                  []*url.URL{uri},
		ExtraExtensions:       []pkix.Extension{ext},
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, a.Cert, csr.PublicKey, a.Key)
	if err != nil {
		return nil, nil, fmt.Errorf("pki: sign client certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, fmt.Errorf("pki: parse issued certificate: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), cert, nil
}

// ServerNames configures the SANs of a gateway server certificate.
type ServerNames struct {
	CommonName  string
	DNSNames    []string
	IPAddresses []net.IP
}

// IssueServerCert issues a TLS server certificate and returns it as a
// tls.Certificate ready for crypto/tls.
func (a *CA) IssueServerCert(names ServerNames, validity time.Duration) (tls.Certificate, error) {
	if validity <= 0 {
		validity = 30 * 24 * time.Hour
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("pki: generate server key: %w", err)
	}
	serial, err := RandomSerial()
	if err != nil {
		return tls.Certificate{}, err
	}
	cn := names.CommonName
	if cn == "" {
		cn = "certgateway-local-gateway"
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn, Organization: []string{"certgateway"}},
		DNSNames:              names.DNSNames,
		IPAddresses:           names.IPAddresses,
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(validity),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, a.Cert, &key.PublicKey, a.Key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("pki: sign server certificate: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("pki: tls keypair: %w", err)
	}
	return tlsCert, nil
}

// VerifyClientCert validates cert against the CA pool for client auth and
// returns the parsed chain.
func (a *CA) VerifyClientCert(cert *x509.Certificate, now time.Time) ([][]*x509.Certificate, error) {
	pool := x509.NewCertPool()
	pool.AddCert(a.Cert)
	opts := x509.VerifyOptions{
		Roots:       pool,
		CurrentTime: now,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	return cert.Verify(opts)
}

func RandomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("pki: generate serial: %w", err)
	}
	return serial, nil
}
