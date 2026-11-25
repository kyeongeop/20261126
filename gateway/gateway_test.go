package gateway_test

import (
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

	"certgateway/gateway"
	"certgateway/identity"
)

func get(t *testing.T, client *http.Client, url string) (int, []byte) {
	t.Helper()
	res, err := client.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	return res.StatusCode, body
}

func TestGatewayAllowsCertificateBoundToService(t *testing.T) {
	env := newTestEnv(t, "billing.internal")
	cert := env.clientCert(t, "billing.internal", identity.PurposeAPI)
	client := env.httpClient(&cert)

	status, body := get(t, client, "https://"+env.gw.Addr()+"/whoami")
	if status != http.StatusOK {
		t.Fatalf("/whoami status = %d, body=%s", status, body)
	}
	var info gateway.IdentityInfo
	if err := json.Unmarshal(body, &info); err != nil {
		t.Fatal(err)
	}
	if info.Service != "billing.internal" || info.Purpose != identity.PurposeAPI {
		t.Fatalf("unexpected identity: %+v", info)
	}

	if status, _ := get(t, client, "https://"+env.gw.Addr()+"/api/invoices"); status != http.StatusOK {
		t.Fatalf("api route status = %d, want 200", status)
	}
}

func TestGatewayRejectsCertificateBoundToOtherService(t *testing.T) {
	env := newTestEnv(t, "billing.internal")
	other := env.clientCert(t, "orders.internal", identity.PurposeAPI)

	if !env.dialRejected(&other) {
		t.Fatal("TLS handshake must be rejected for a certificate bound to another service")
	}

	client := env.httpClient(&other)
	if _, err := client.Get("https://" + env.gw.Addr() + "/whoami"); err == nil {
		t.Fatal("HTTP request with wrong-service certificate must fail")
	}
}

func TestGatewayRejectsMissingClientCertificate(t *testing.T) {
	env := newTestEnv(t, "billing.internal")
	if !env.dialRejected(nil) {
		t.Fatal("handshake without client certificate must be rejected")
	}
}

func TestGatewayEnforcesPurposePerRoute(t *testing.T) {
	env := newTestEnv(t, "billing.internal")

	metricsCert := env.clientCert(t, "billing.internal", identity.PurposeMetrics)
	metricsClient := env.httpClient(&metricsCert)
	if status, body := get(t, metricsClient, "https://"+env.gw.Addr()+"/metrics"); status != http.StatusOK {
		t.Fatalf("metrics cert /metrics = %d body=%s", status, body)
	}
	if status, _ := get(t, metricsClient, "https://"+env.gw.Addr()+"/api/invoices"); status != http.StatusForbidden {
		t.Fatalf("metrics cert /api status = %d, want 403", status)
	}
	if status, _ := get(t, metricsClient, "https://"+env.gw.Addr()+"/admin/users"); status != http.StatusForbidden {
		t.Fatalf("metrics cert /admin status = %d, want 403", status)
	}

	adminCert := env.clientCert(t, "billing.internal", identity.PurposeAdmin)
	adminClient := env.httpClient(&adminCert)
	if status, body := get(t, adminClient, "https://"+env.gw.Addr()+"/admin/users"); status != http.StatusOK {
		t.Fatalf("admin cert /admin = %d body=%s", status, body)
	}
}

func TestGatewayRejectsExpiredCertificate(t *testing.T) {
	env := newTestEnv(t, "billing.internal")
	key, err := generateTestKey()
	if err != nil {
		t.Fatal(err)
	}
	cert := issueAt(t, env, key, "billing.internal", identity.PurposeAPI,
		time.Now().Add(-2*time.Hour), time.Hour)
	if !env.dialRejected(&cert) {
		t.Fatal("expired client certificate must be rejected at TLS handshake")
	}
}
