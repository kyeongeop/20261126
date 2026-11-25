package pki_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"testing"
	"time"

	"certgateway/identity"
	"certgateway/pki"
)

func newCSR(t *testing.T) (*x509.CertificateRequest, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: "test-client"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatal(err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
	return csr, csrPEM
}

func TestCAIssuesVerifiableServiceBoundClientCert(t *testing.T) {
	ca, err := pki.NewRootCA("test-ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	csr, _ := newCSR(t)
	binding := identity.Binding{Service: "billing.internal", Purpose: identity.PurposeMetrics, InvitationID: "inv_42"}
	now := time.Now()

	certPEM, cert, err := ca.SignClientCSR(csr, binding, nil, 2*time.Hour, now)
	if err != nil {
		t.Fatalf("SignClientCSR: %v", err)
	}
	wantNotAfter := now.Add(2 * time.Hour).Truncate(time.Second)
	if !cert.NotAfter.Equal(wantNotAfter) {
		t.Fatalf("NotAfter = %v, want %v", cert.NotAfter, wantNotAfter)
	}
	if len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Fatalf("expected exactly ClientAuth EKU, got %v", cert.ExtKeyUsage)
	}
	if cert.IsCA {
		t.Fatal("client certificate must not be a CA")
	}

	if _, err := ca.VerifyClientCert(cert, now.Add(time.Minute)); err != nil {
		t.Fatalf("chain verification: %v", err)
	}
	if _, err := ca.VerifyClientCert(cert, now.Add(3*time.Hour)); err == nil {
		t.Fatal("expired certificate must not verify")
	}

	got, err := identity.Check(cert, "billing.internal", identity.PurposeMetrics)
	if err != nil {
		t.Fatalf("binding check: %v", err)
	}
	if got != binding {
		t.Fatalf("binding = %+v, want %+v", got, binding)
	}

	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatal("issued PEM is not a CERTIFICATE block")
	}
}

func TestSignRejectsInvalidInputs(t *testing.T) {
	ca, err := pki.NewRootCA("test-ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	csr, _ := newCSR(t)
	good := identity.Binding{Service: "s", Purpose: identity.PurposeAPI, InvitationID: "i"}

	if _, _, err := ca.SignClientCSR(nil, good, nil, time.Hour, time.Time{}); err == nil {
		t.Fatal("expected error for nil CSR")
	}
	if _, _, err := ca.SignClientCSR(csr, identity.Binding{}, nil, time.Hour, time.Time{}); err == nil {
		t.Fatal("expected error for invalid binding")
	}
	if _, _, err := ca.SignClientCSR(csr, good, nil, 0, time.Time{}); err == nil {
		t.Fatal("expected error for zero validity")
	}
}

func TestIssueServerCert(t *testing.T) {
	ca, _ := pki.NewRootCA("test-ca", time.Hour)
	tlsCert, err := ca.IssueServerCert(pki.ServerNames{
		CommonName: "localhost", DNSNames: []string{"localhost"}, IPAddresses: nil,
	}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if len(tlsCert.Certificate) == 0 {
		t.Fatal("expected at least one DER certificate")
	}
}
