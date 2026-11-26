package gateway

import (
	"bytes"
	"crypto/tls"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestTLSRoutingPriority(t *testing.T) {
	snapshot := testSnapshot(t, UnknownPolicyDefault, map[string]string{
		"shop.example.com": "exact",
		"*.example.com":    "wildcard",
	}, "default")
	server := startTestServer(t, NewStore(snapshot), ServerOptions{Logger: discardLogger()})

	tests := []struct {
		name       string
		serverName string
		verify     bool
		wantOrg    string
	}{
		{name: "explicit route", serverName: "shop.example.com", verify: true, wantOrg: "Exact Route"},
		{name: "wildcard route", serverName: "api.example.com", verify: true, wantOrg: "Wildcard Route"},
		{name: "default for unknown", serverName: "unknown.example.org", verify: false, wantOrg: "Default Certificate"},
		{name: "default for no SNI", serverName: "", verify: false, wantOrg: "Default Certificate"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			conn, _ := dialTLS(t, server.Addr().String(), test.serverName, test.verify)
			defer conn.Close()
			if got := peerOrganization(t, conn); got != test.wantOrg {
				t.Fatalf("peer organization = %q, want %q", got, test.wantOrg)
			}
		})
	}
}

func TestUnknownSNIRejectHandshake(t *testing.T) {
	snapshot := testSnapshot(t, UnknownPolicyReject, map[string]string{
		"*.example.com": "wildcard",
	}, "")
	server := startTestServer(t, NewStore(snapshot), ServerOptions{Logger: discardLogger()})

	known, _ := dialTLS(t, server.Addr().String(), "api.example.com", true)
	known.Close()

	for _, serverName := range []string{"unknown.example.org", ""} {
		raw, err := net.DialTimeout("tcp", server.Addr().String(), 2*time.Second)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		client := tls.Client(raw, clientTLSConfig(t, serverName, false))
		err = client.Handshake()
		raw.Close()
		if err == nil {
			t.Fatalf("handshake for SNI %q succeeded, want disabled handshake", serverName)
		}
	}
}

func TestSelectionIsWrittenToDebugLog(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))

	snapshot := testSnapshot(t, UnknownPolicyDefault, map[string]string{
		"shop.example.com": "exact",
		"*.example.com":    "wildcard",
	}, "default")
	server := startTestServer(t, NewStore(snapshot), ServerOptions{Logger: logger})

	conn, _ := dialTLS(t, server.Addr().String(), "shop.example.com", true)
	conn.Close()

	output := logs.String()
	for _, want := range []string{
		"sni certificate routing decision",
		`"sni":"shop.example.com"`,
		`"result":"exact"`,
		`"certificate":"exact"`,
		`"config_generation":1`,
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("debug log does not contain %q:\n%s", want, output)
		}
	}
}

func TestReloadUsesSnapshotCapturedPerConnection(t *testing.T) {
	oldSnapshot := testSnapshot(t, UnknownPolicyDefault, map[string]string{
		"shop.example.com": "exact",
	}, "default")
	newSnapshot := testSnapshot(t, UnknownPolicyDefault, map[string]string{
		"*.example.com": "wildcard",
	}, "default")
	store := NewStore(oldSnapshot)

	accepted := make(chan net.Addr, 4)
	handled := make(chan ConnectionInfo, 4)
	server := startTestServer(t, store, ServerOptions{
		Logger: discardLogger(),
		Handler: func(info ConnectionInfo) {
			handled <- info
		},
		OnAccept: func(addr net.Addr) {
			accepted <- addr
		},
	})

	rawOld, err := net.DialTimeout("tcp", server.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial old connection: %v", err)
	}
	select {
	case <-accepted:
	case <-time.After(2 * time.Second):
		rawOld.Close()
		t.Fatal("server did not accept the old connection")
	}

	if generation := store.Set(newSnapshot); generation != 2 {
		t.Fatalf("new snapshot generation = %d, want 2", generation)
	}

	oldClient := tls.Client(rawOld, clientTLSConfig(t, "shop.example.com", true))
	if err := oldClient.Handshake(); err != nil {
		rawOld.Close()
		t.Fatalf("old connection handshake: %v", err)
	}
	if got := peerOrganization(t, oldClient); got != "Exact Route" {
		t.Fatalf("old connection peer organization = %q, want exact route certificate", got)
	}
	oldInfo := waitForConnectionInfo(t, handled)
	if oldInfo.Generation != 1 || oldInfo.Selection.Kind != MatchExact {
		t.Fatalf("old connection used generation=%d kind=%q, want generation=1 kind=exact",
			oldInfo.Generation, oldInfo.Selection.Kind)
	}
	oldClient.Close()

	newClient, _ := dialTLS(t, server.Addr().String(), "shop.example.com", true)
	defer newClient.Close()
	if got := peerOrganization(t, newClient); got != "Wildcard Route" {
		t.Fatalf("new connection peer organization = %q, want wildcard route certificate", got)
	}
	newInfo := waitForConnectionInfo(t, handled)
	if newInfo.Generation != 2 || newInfo.Selection.Kind != MatchWildcard {
		t.Fatalf("new connection used generation=%d kind=%q, want generation=2 kind=wildcard",
			newInfo.Generation, newInfo.Selection.Kind)
	}
}

func waitForConnectionInfo(t *testing.T, channel <-chan ConnectionInfo) ConnectionInfo {
	t.Helper()
	select {
	case info := <-channel:
		return info
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for a completed connection")
		return ConnectionInfo{}
	}
}
