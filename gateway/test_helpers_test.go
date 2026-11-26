package gateway

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate test source file")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), ".."))
}

func repoFile(t *testing.T, parts ...string) string {
	t.Helper()
	path := filepath.Join(append([]string{repoRoot(t)}, parts...)...)
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("repository fixture %q: %v", path, err)
	}
	return path
}

func testCertificates(t *testing.T) map[string]*Certificate {
	t.Helper()
	specs := []struct {
		name string
		file string
	}{
		{name: "exact", file: "exact-shop"},
		{name: "wildcard", file: "wildcard-example"},
		{name: "default", file: "default"},
	}
	certificates := make(map[string]*Certificate, len(specs))
	for _, spec := range specs {
		cert, err := loadCertificate(
			spec.name,
			repoFile(t, "certs", spec.file+".pem"),
			repoFile(t, "certs", spec.file+"-key.pem"),
		)
		if err != nil {
			t.Fatalf("load test certificate %q: %v", spec.name, err)
		}
		certificates[spec.name] = cert
	}
	return certificates
}

func testSnapshot(t *testing.T, policy UnknownPolicy, routes map[string]string, defaultName string) *Snapshot {
	t.Helper()
	certificates := testCertificates(t)
	snapshot := &Snapshot{
		loadedAt:      time.Now().UTC(),
		unknownPolicy: policy,
		exact:         make(map[string]*route),
	}
	for pattern, certName := range routes {
		host, wildcard, suffix, err := normalizePattern(pattern)
		if err != nil {
			t.Fatalf("normalize route %q: %v", pattern, err)
		}
		cert := certificates[certName]
		if cert == nil {
			t.Fatalf("test route %q references unknown certificate %q", pattern, certName)
		}
		if wildcard {
			snapshot.wildcards = append(snapshot.wildcards, &route{
				host: host, wildcard: true, suffix: suffix, certificate: cert,
			})
			continue
		}
		snapshot.exact[host] = &route{host: host, certificate: cert}
	}
	sortWildcards(snapshot.wildcards)
	if defaultName != "" {
		snapshot.defaultCertificate = certificates[defaultName]
	}
	return snapshot
}

func rootPool(t *testing.T) *x509.CertPool {
	t.Helper()
	data, err := os.ReadFile(repoFile(t, "certs", "ca.pem"))
	if err != nil {
		t.Fatalf("read CA: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		t.Fatal("append development CA")
	}
	return pool
}

func clientTLSConfig(t *testing.T, serverName string, verify bool) *tls.Config {
	t.Helper()
	config := &tls.Config{
		ServerName: serverName,
		MinVersion: tls.VersionTLS12,
	}
	if verify {
		config.RootCAs = rootPool(t)
	} else {
		config.InsecureSkipVerify = true
	}
	return config
}

func startTestServer(t *testing.T, store *Store, options ServerOptions) *Server {
	t.Helper()
	server, err := Listen("127.0.0.1:0", store, options)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = server.Serve(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		_ = server.Close()
		server.Wait()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Log("server Serve did not return within cleanup timeout")
		}
	})
	return server
}

func dialTLS(t *testing.T, address, serverName string, verify bool) (*tls.Conn, *net.TCPConn) {
	t.Helper()
	raw, err := net.DialTimeout("tcp", address, 2*time.Second)
	if err != nil {
		t.Fatalf("dial %s: %v", address, err)
	}
	client := tls.Client(raw, clientTLSConfig(t, serverName, verify))
	if err := client.Handshake(); err != nil {
		raw.Close()
		t.Fatalf("TLS handshake for SNI %q: %v", serverName, err)
	}
	tcp, _ := raw.(*net.TCPConn)
	return client, tcp
}

func peerOrganization(t *testing.T, conn *tls.Conn) string {
	t.Helper()
	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 || len(state.PeerCertificates[0].Subject.Organization) == 0 {
		t.Fatal("peer certificate has no organization")
	}
	return state.PeerCertificates[0].Subject.Organization[0]
}
