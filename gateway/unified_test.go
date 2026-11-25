package gateway_test

import (
	"context"
	"net"
	"net/http"
	"testing"
	"time"

	"certgateway/enroll"
	"certgateway/gateway"
	"certgateway/identity"
	"certgateway/invitation"
	"certgateway/pki"
)

func TestUnifiedTLSGatewayServesEnrollmentAndProtectsBusiness(t *testing.T) {
	env := newTestEnv(t, "billing.internal")

	store := invitation.NewStore()
	svc := enroll.NewService(store, env.ca)
	enrollHandler := enroll.NewHandler(svc, "unified-admin")

	serverCert, err := env.ca.IssueServerCert(pki.ServerNames{
		CommonName:  "localhost",
		DNSNames:    []string{"localhost"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}, 30*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	ugw, err := gateway.StartUnified(gateway.UnifiedConfig{
		CA: env.ca, ServerCert: serverCert, ServiceName: "billing.internal",
		EnrollHandler: enrollHandler,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ugw.Close() })

	ctx := context.Background()
	// Enrollment API is reached over HTTPS with server trust but NO client cert.
	api := &enroll.Client{
		BaseURL:    "https://" + ugw.Addr(),
		HTTPClient: env.httpClient(nil),
	}
	inv, err := api.CreateInvitation(ctx, "unified-admin", enroll.CreateInvitationInput{
		Service: "billing.internal", Purpose: identity.PurposeAPI,
		InviteTTL: time.Minute, CertTTL: time.Hour,
	})
	if err != nil {
		t.Fatalf("admin invite over unified TLS: %v", err)
	}
	enrolled, err := api.Enroll(ctx, inv.Token)
	if err != nil {
		t.Fatalf("enroll over TLS without client cert: %v", err)
	}
	cert, err := enrolled.TLSCertificate()
	if err != nil {
		t.Fatal(err)
	}

	// Enrolled certificate reaches business route.
	mtlsClient := env.httpClient(&cert)
	status, body := get(t, mtlsClient, "https://"+ugw.Addr()+"/whoami")
	if status != http.StatusOK {
		t.Fatalf("enrolled cert /whoami = %d body=%s", status, body)
	}

	// Anonymous TLS is fine for enrollment but business route answers 401.
	anonClient := env.httpClient(nil)
	res, err := anonClient.Get("https://" + ugw.Addr() + "/whoami")
	if err != nil {
		t.Fatalf("anonymous TLS GET should complete at HTTP layer: %v", err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("anonymous /whoami status = %d, want 401", res.StatusCode)
	}

	// A valid CA-signed cert for another service completes TLS but gets 403.
	other := env.clientCert(t, "orders.internal", identity.PurposeAPI)
	otherClient := env.httpClient(&other)
	res2, err := otherClient.Get("https://" + ugw.Addr() + "/whoami")
	if err != nil {
		t.Fatalf("wrong-service GET should complete at HTTP layer: %v", err)
	}
	res2.Body.Close()
	if res2.StatusCode != http.StatusForbidden {
		t.Fatalf("wrong-service /whoami status = %d, want 403", res2.StatusCode)
	}
}
