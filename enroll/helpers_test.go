package enroll_test

import (
	"crypto/x509"
	"encoding/pem"
	"testing"
)

func decodeCert(t *testing.T, certPEM []byte) *pem.Block {
	t.Helper()
	block, rest := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("expected CERTIFICATE PEM, rest=%d bytes", len(rest))
	}
	return block
}

func parseCert(block *pem.Block) (*x509.Certificate, error) {
	return x509.ParseCertificate(block.Bytes)
}
