// Root end-to-end test: the complete one-time-invitation enrollment and mTLS
// gateway flow over real localhost TCP listeners.
package certgateway_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"certgateway/clock"
	"certgateway/enroll"
	"certgateway/gateway"
	"certgateway/identity"
	"certgateway/invitation"
	"certgateway/pki"
)

type stack struct {
	ca         *pki.CA
	apiClient  *enroll.Client
	gateway    *gateway.Gateway
	clock      *clock.Clock
	store      *invitation.Store
	adminToken string
}

func startStack(t *testing.T, gatewayService string) *stack {
	t.Helper()
	ca, err := pki.NewRootCA("e2e-ca", 365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	clk := clock.New()
	store := invitation.NewStore()
	store.NowFunc = clk.Now
	svc := enroll.NewService(store, ca)
	adminToken := "e2e-admin-token"

	apiLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	apiSrv := &http.Server{Handler: enroll.NewHandler(svc, adminToken)}
	go apiSrv.Serve(apiLn)
	t.Cleanup(func() { apiSrv.Close() })

	serverCert, err := ca.IssueServerCert(pki.ServerNames{
		CommonName:  "localhost",
		DNSNames:    []string{"localhost"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}, 30*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	gw, err := gateway.Start(gateway.Config{
		CA: ca, ServerCert: serverCert, ServiceName: gatewayService,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { gw.Close() })

	return &stack{
		ca: ca,
		apiClient: &enroll.Client{
			BaseURL:    "http://" + apiLn.Addr().String(),
			HTTPClient: &http.Client{Timeout: 5 * time.Second},
		},
		gateway:    gw,
		clock:      clk,
		store:      store,
		adminToken: adminToken,
	}
}

func (s *stack) mtlsClient(cert tls.Certificate) *http.Client {
	pool := x509.NewCertPool()
	pool.AddCert(s.ca.Cert)
	return &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:      pool,
				ServerName:   "localhost",
				Certificates: []tls.Certificate{cert},
			},
		},
	}
}

func TestOneTimeInvitationEnrollsAndAccessesBoundService(t *testing.T) {
	ctx := context.Background()
	st := startStack(t, "billing.internal")

	inv, err := st.apiClient.CreateInvitation(ctx, st.adminToken, enroll.CreateInvitationInput{
		Service: "billing.internal", Purpose: identity.PurposeAPI,
		InviteTTL: 10 * time.Minute, CertTTL: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}

	enrolled, err := st.apiClient.Enroll(ctx, inv.Token)
	if err != nil {
		t.Fatalf("client self-enrollment failed: %v", err)
	}
	cert, err := enrolled.TLSCertificate()
	if err != nil {
		t.Fatal(err)
	}

	// The one-time invitation must not allow another certificate.
	if _, err := st.apiClient.Enroll(ctx, inv.Token); err == nil {
		t.Fatal("invitation token was reusable")
	}

	// The issued certificate reaches the service it is bound to.
	hc := st.mtlsClient(cert)
	res, err := hc.Get("https://" + st.gateway.Addr() + "/whoami")
	if err != nil {
		t.Fatalf("mTLS /whoami: %v", err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status %d body=%s", res.StatusCode, body)
	}
	var who gateway.IdentityInfo
	if err := json.Unmarshal(body, &who); err != nil {
		t.Fatal(err)
	}
	if who.Service != "billing.internal" || who.Purpose != identity.PurposeAPI || who.InvitationID != inv.ID {
		t.Fatalf("unexpected whoami identity: %+v", who)
	}
}

func TestCertificateForOtherServiceCannotReachGateway(t *testing.T) {
	ctx := context.Background()
	st := startStack(t, "billing.internal")

	inv, err := st.apiClient.CreateInvitation(ctx, st.adminToken, enroll.CreateInvitationInput{
		Service: "analytics.internal", Purpose: identity.PurposeAPI,
		InviteTTL: time.Minute, CertTTL: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	enrolled, err := st.apiClient.Enroll(ctx, inv.Token)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := enrolled.TLSCertificate()

	hc := st.mtlsClient(cert)
	if _, err := hc.Get("https://" + st.gateway.Addr() + "/whoami"); err == nil {
		t.Fatal("analytics certificate unexpectedly reached billing gateway")
	}
}

func TestExpiredInvitationCannotEnrollOverHTTP(t *testing.T) {
	ctx := context.Background()
	st := startStack(t, "billing.internal")

	_, token, err := st.store.Create(invitation.CreateInput{
		Service: "billing.internal", Purpose: identity.PurposeAPI,
		InviteTTL: time.Minute, CertValidity: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	st.clock.Advance(2 * time.Minute)

	if _, err := st.apiClient.Enroll(ctx, token); err == nil {
		t.Fatal("expired invitation unexpectedly enrolled over HTTP")
	}
}
