package enroll_test

import (
	"context"
	"crypto/x509"
	"net"
	"net/http"
	"testing"
	"time"

	"certgateway/enroll"
	"certgateway/identity"
	"certgateway/invitation"
	"certgateway/pki"
)

func startTestAPI(t *testing.T, adminToken string) (*enroll.Client, *pki.CA) {
	t.Helper()
	ca, err := pki.NewRootCA("http-test-ca", 365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	svc := enroll.NewService(invitation.NewStore(), ca)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: enroll.NewHandler(svc, adminToken)}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return &enroll.Client{BaseURL: "http://" + ln.Addr().String(), HTTPClient: &http.Client{Timeout: 5 * time.Second}}, ca
}

func TestHTTPAdminAuthAndEnrollment(t *testing.T) {
	client, ca := startTestAPI(t, "secret-admin")
	ctx := context.Background()

	if _, err := client.CreateInvitation(ctx, "wrong-token", enroll.CreateInvitationInput{
		Service: "billing.internal", Purpose: identity.PurposeAPI, InviteTTL: time.Minute, CertTTL: time.Hour,
	}); err == nil {
		t.Fatal("expected admin creation with wrong token to fail")
	}

	inv, err := client.CreateInvitation(ctx, "secret-admin", enroll.CreateInvitationInput{
		Service: "billing.internal", Purpose: identity.PurposeMetrics, InviteTTL: time.Minute, CertTTL: time.Hour,
	})
	if err != nil {
		t.Fatalf("CreateInvitation: %v", err)
	}
	if inv.Token == "" || inv.ID == "" {
		t.Fatal("expected one-time token in admin response")
	}

	enrolled, err := client.Enroll(ctx, inv.Token)
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	tlsCert, err := enrolled.TLSCertificate()
	if err != nil {
		t.Fatal(err)
	}
	if len(tlsCert.Certificate) < 1 {
		t.Fatal("expected leaf certificate")
	}

	leaf, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ca.VerifyClientCert(leaf, time.Now()); err != nil {
		t.Fatalf("certificate verify: %v", err)
	}
	binding, err := identity.Check(leaf, "billing.internal", identity.PurposeMetrics)
	if err != nil {
		t.Fatalf("binding: %v", err)
	}
	if binding.InvitationID != inv.ID {
		t.Fatalf("invitation id = %q, want %q", binding.InvitationID, inv.ID)
	}

	// One-time token cannot enroll a second time.
	if _, err := client.Enroll(ctx, inv.Token); err == nil {
		t.Fatal("second enrollment with consumed token must fail")
	}
}

func TestHTTPEnrollRejectsBogusToken(t *testing.T) {
	client, _ := startTestAPI(t, "admin")
	if _, err := client.Enroll(context.Background(), "bogus-token"); err == nil {
		t.Fatal("expected enrollment with bogus token to fail")
	}
}

func TestHTTPAdminDisabledWithoutToken(t *testing.T) {
	client, _ := startTestAPI(t, "")
	if _, err := client.CreateInvitation(context.Background(), "anything", enroll.CreateInvitationInput{
		Service: "s", Purpose: identity.PurposeAPI,
	}); err == nil {
		t.Fatal("expected admin API to be disabled when no token configured")
	}
}
