package enroll

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
)

// GenerateKey creates a P-256 ECDSA client key.
func GenerateKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// CreateCSRPEM builds and signs a PKCS#10 CSR for key.
func CreateCSRPEM(key *ecdsa.PrivateKey, commonName string) (csrDER, csrPEM []byte, err error) {
	if commonName == "" {
		commonName = "certgateway-client"
	}
	csrDER, err = x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: commonName}}, key)
	if err != nil {
		return nil, nil, fmt.Errorf("enroll: create CSR: %w", err)
	}
	csrPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	return csrDER, csrPEM, nil
}

// EnrolledKey pairs a issued certificate chain with its private key and offers
// a ready-to-use crypto/tls client certificate.
type EnrolledKey struct {
	PrivateKey     *ecdsa.PrivateKey
	KeyPEM         []byte
	CertificatePEM []byte
	ChainPEM       []byte
}

// TLSCertificate returns an X509 key pair for mTLS clients.
func (e *EnrolledKey) TLSCertificate() (tls.Certificate, error) {
	return tls.X509KeyPair(e.ChainPEM, e.KeyPEM)
}

// EncodeECPrivateKey PEM-encodes an EC private key.
func EncodeECPrivateKey(key *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("enroll: marshal key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), nil
}
