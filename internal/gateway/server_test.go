package gateway_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"offlinegw/internal/gateway"
	"offlinegw/internal/revoke"
	"offlinegw/internal/testutil"
)

var (
	now        = time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	thisUpdate = now.Add(-time.Hour)
)

type fixture struct {
	ca       *testutil.CA
	source   *revoke.Source
	auditBuf *bytes.Buffer
	addr     string
	cancel   context.CancelFunc
}

func startGateway(t *testing.T, policy revoke.StalePolicy) *fixture {
	t.Helper()
	ca := testutil.NewCA(t, "gw-ca")
	src := &revoke.Source{}
	f := &fixture{ca: ca, source: src, auditBuf: &bytes.Buffer{}}
	srv := gateway.NewServer(gateway.Config{
		Certificates: []tls.Certificate{ca.Issue(t, "server", 100, true)},
		ClientCAs:    poolWith(ca),
		Verifier:     &revoke.Verifier{Source: src, StalePolicy: policy, Now: func() time.Time { return now }},
		Audit:        revoke.NewAuditLogger(f.auditBuf),
	})
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f.addr = l.Addr().String()
	ctx, cancel := context.WithCancel(context.Background())
	f.cancel = cancel
	go func() { _ = srv.Serve(ctx, l) }()
	t.Cleanup(cancel)
	return f
}

// pinCRL issues a CRL from the fixture CA and pins it into the source.
func (f *fixture) pinCRL(t *testing.T, serials []int64, nextUpdate time.Time) {
	t.Helper()
	path := t.TempDir() + "/pinned.crl"
	crl := f.ca.CreateCRL(t, serials, thisUpdate, nextUpdate)
	if err := os.WriteFile(path, crl, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := f.source.LoadCRLFile(path, f.ca.Cert); err != nil {
		t.Fatal(err)
	}
}

func poolWith(ca *testutil.CA) *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)
	return pool
}

func dial(t *testing.T, addr string, ca *testutil.CA, client tls.Certificate) (string, error) {
	t.Helper()
	conn, err := tls.Dial("tcp", addr, &tls.Config{
		RootCAs:      poolWith(ca),
		Certificates: []tls.Certificate{client},
		ServerName:   "localhost",
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		return "", err
	}
	defer conn.Close()
	line, err := bufio.NewReader(conn).ReadString('\n')
	return strings.TrimSpace(line), err
}

func (f *fixture) auditEntries(t *testing.T) []map[string]any {
	t.Helper()
	var entries []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(f.auditBuf.String()), "\n") {
		if line == "" {
			continue
		}
		var entry map[string]any
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatal(err)
		}
		entries = append(entries, entry)
	}
	return entries
}

func TestGatewayAllowsGoodClient(t *testing.T) {
	f := startGateway(t, revoke.StaleDeny)
	// No CRL pinned: unknown status must be denied.
	if _, err := dial(t, f.addr, f.ca, f.ca.Issue(t, "c1", 1, false)); err == nil {
		t.Fatal("expected handshake failure without pinned revocation data")
	}
	entries := f.auditEntries(t)
	if len(entries) == 0 || entries[0]["decision"] != "deny" {
		t.Fatalf("audit = %v", entries)
	}
	if !strings.Contains(entries[0]["reason"].(string), "no pinned CRL or OCSP") {
		t.Fatalf("reason = %v", entries[0]["reason"])
	}
}

func TestGatewayRevokedClientRejected(t *testing.T) {
	f := startGateway(t, revoke.StaleDeny)
	f.pinCRL(t, []int64{2}, now.Add(time.Hour))
	if _, err := dial(t, f.addr, f.ca, f.ca.Issue(t, "revoked-client", 2, false)); err == nil {
		t.Fatal("expected revoked client to be rejected")
	}
	line, err := dial(t, f.addr, f.ca, f.ca.Issue(t, "good-client", 3, false))
	if err != nil {
		t.Fatalf("good client rejected: %v", err)
	}
	if line != "OK mode=full" {
		t.Fatalf("banner = %q", line)
	}
	entries := f.auditEntries(t)
	if len(entries) != 2 {
		t.Fatalf("expected 2 audit entries, got %d", len(entries))
	}
	if entries[0]["decision"] != "deny" || !strings.Contains(entries[0]["reason"].(string), "revoked") {
		t.Fatalf("deny entry = %v", entries[0])
	}
	if entries[1]["decision"] != "allow" {
		t.Fatalf("allow entry = %v", entries[1])
	}
}

func TestGatewayStaleDegrade(t *testing.T) {
	f := startGateway(t, revoke.StaleDegrade)
	f.pinCRL(t, nil, now.Add(-time.Minute))
	line, err := dial(t, f.addr, f.ca, f.ca.Issue(t, "stale-client", 4, false))
	if err != nil {
		t.Fatalf("degraded client rejected: %v", err)
	}
	if line != "OK mode=degraded" {
		t.Fatalf("banner = %q", line)
	}
	entries := f.auditEntries(t)
	if len(entries) == 0 || entries[0]["decision"] != "degrade" {
		t.Fatalf("audit = %v", entries)
	}
	if !strings.Contains(entries[0]["reason"].(string), "stale-policy=degrade") {
		t.Fatalf("reason = %v", entries[0]["reason"])
	}
}

func TestGatewayStaleDeny(t *testing.T) {
	f := startGateway(t, revoke.StaleDeny)
	f.pinCRL(t, nil, now.Add(-time.Minute))
	if _, err := dial(t, f.addr, f.ca, f.ca.Issue(t, "stale-client", 5, false)); err == nil {
		t.Fatal("expected stale CRL with deny policy to reject")
	}
	entries := f.auditEntries(t)
	if len(entries) == 0 || entries[0]["decision"] != "deny" {
		t.Fatalf("audit = %v", entries)
	}
	if !strings.Contains(entries[0]["reason"].(string), "stale-policy=deny") {
		t.Fatalf("reason = %v", entries[0]["reason"])
	}
}
