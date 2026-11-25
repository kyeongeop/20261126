package gateway_test

import (
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"testing"
	"time"

	"certgateway/enroll"
	"certgateway/gateway"
	"certgateway/identity"
	"certgateway/pki"
)

type testEnv struct {
	ca *pki.CA
	gw *gateway.Gateway
}

func newTestEnv(t *testing.T, service string) *testEnv {
	t.Helper()
	ca, err := pki.NewRootCA("gateway-test-ca", 365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	serverCert, err := ca.IssueServerCert(pki.ServerNames{
		CommonName:  "localhost",
		DNSNames:    []string{"localhost"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}, 30*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	gw, err := gateway.Start(gateway.Config{
		CA: ca, ServerCert: serverCert, ServiceName: service,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { gw.Close() })
	return &testEnv{ca: ca, gw: gw}
}

// clientCert issues a key and a service-bound certificate directly from the CA.
func (e *testEnv) clientCert(t *testing.T, service, purpose string) tls.Certificate {
	t.Helper()
	key, err := enroll.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	_, csrPEM, err := enroll.CreateCSRPEM(key, "")
	if err != nil {
		t.Fatal(err)
	}
	csr, err := enroll.ParseCSRPEM(csrPEM)
	if err != nil {
		t.Fatal(err)
	}
	binding := identity.Binding{Service: service, Purpose: purpose, InvitationID: "inv-test"}
	certPEM, _, err := e.ca.SignClientCSR(csr, binding, nil, time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := enroll.EncodeECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return tlsCert
}

func (e *testEnv) httpClient(cert *tls.Certificate) *http.Client {
	pool := x509.NewCertPool()
	pool.AddCert(e.ca.Cert)
	tlsCfg := &tls.Config{RootCAs: pool, ServerName: "localhost"}
	if cert != nil {
		tlsCfg.Certificates = []tls.Certificate{*cert}
	}
	return &http.Client{
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
		Timeout:   5 * time.Second,
	}
}

// dialRejected reports whether a fresh mTLS connection is rejected. TLS 1.3
// lets the client finish its handshake flight before the server's
// certificate-rejection alert arrives, so a successful tls.Dial is followed
// by a Read that observes the alert/closure. A read timeout means the server
// accepted the certificate and is waiting for an HTTP request.
func (e *testEnv) dialRejected(cert *tls.Certificate) bool {
	pool := x509.NewCertPool()
	pool.AddCert(e.ca.Cert)
	tlsCfg := &tls.Config{RootCAs: pool, ServerName: "localhost"}
	if cert != nil {
		tlsCfg.Certificates = []tls.Certificate{*cert}
	}
	conn, err := tls.Dial("tcp", e.gw.Addr(), tlsCfg)
	if err != nil {
		return true
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1)
	if _, err := conn.Read(buf); err != nil {
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			return false
		}
		return true
	}
	return false
}

func generateTestKey() (*ecdsa.PrivateKey, error) {
	return enroll.GenerateKey()
}

// issueAt issues a certificate with an explicit signing clock, allowing
// deterministic creation of expired certificates.
func issueAt(t *testing.T, e *testEnv, key *ecdsa.PrivateKey, service, purpose string, now time.Time, validity time.Duration) tls.Certificate {
	t.Helper()
	_, csrPEM, err := enroll.CreateCSRPEM(key, "")
	if err != nil {
		t.Fatal(err)
	}
	csr, err := enroll.ParseCSRPEM(csrPEM)
	if err != nil {
		t.Fatal(err)
	}
	binding := identity.Binding{Service: service, Purpose: purpose, InvitationID: "inv-expired"}
	certPEM, _, err := e.ca.SignClientCSR(csr, binding, nil, validity, now)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := enroll.EncodeECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return tlsCert
}
