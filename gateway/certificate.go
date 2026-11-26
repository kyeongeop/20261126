package gateway

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"os"
)

// Certificate is a loaded certificate/key pair plus the metadata needed for
// routing decisions and debug logs.
type Certificate struct {
	Name string
	TLS  tls.Certificate
	Leaf *x509.Certificate

	fingerprintSHA256 string
}

// FingerprintSHA256 returns the lower-case SHA-256 fingerprint of the leaf.
func (c *Certificate) FingerprintSHA256() string {
	if c == nil {
		return ""
	}
	return c.fingerprintSHA256
}

// Subject returns the leaf certificate subject in RFC 2253 form.
func (c *Certificate) Subject() string {
	if c == nil || c.Leaf == nil {
		return ""
	}
	return c.Leaf.Subject.String()
}

func loadCertificate(name, certFile, keyFile string) (*Certificate, error) {
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return nil, fmt.Errorf("read certificate %q: %w", certFile, err)
	}
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("read private key %q: %w", keyFile, err)
	}

	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("load certificate %q / key %q: %w", certFile, keyFile, err)
	}

	leaf := pair.Leaf
	if leaf == nil {
		if len(pair.Certificate) == 0 {
			return nil, fmt.Errorf("certificate %q contains no certificates", certFile)
		}
		leaf, err = x509.ParseCertificate(pair.Certificate[0])
		if err != nil {
			return nil, fmt.Errorf("parse leaf certificate %q: %w", certFile, err)
		}
		pair.Leaf = leaf
	}

	sum := sha256.Sum256(leaf.Raw)
	return &Certificate{
		Name:              name,
		TLS:               pair,
		Leaf:              leaf,
		fingerprintSHA256: hex.EncodeToString(sum[:]),
	}, nil
}
