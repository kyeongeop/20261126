package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"certgateway/enroll"
	"certgateway/gateway"
	"certgateway/identity"
	"certgateway/invitation"
	"certgateway/pki"
)

func runDemo() error {
	ctx := context.Background()
	ca, err := pki.NewRootCA("demo-ca", 365*24*time.Hour)
	if err != nil {
		return err
	}

	store := invitation.NewStore()
	svc := enroll.NewService(store, ca)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	apiSrv := &http.Server{Handler: enroll.NewHandler(svc, "demo-admin")}
	go apiSrv.Serve(ln)
	defer apiSrv.Close()
	api := &enroll.Client{BaseURL: "http://" + ln.Addr().String()}

	fmt.Println("1. operator creates one-time invitation for billing.internal / api")
	inv, err := api.CreateInvitation(ctx, "demo-admin", enroll.CreateInvitationInput{
		Service: "billing.internal", Purpose: identity.PurposeAPI,
		InviteTTL: 10 * time.Minute, CertTTL: 24 * time.Hour,
	})
	if err != nil {
		return err
	}
	fmt.Printf("   invitation %s expires %s\n", inv.ID, inv.ExpiresAt.Format(time.RFC3339))

	fmt.Println("2. client generates key, solves challenge and enrolls over HTTP")
	enrolled, err := api.Enroll(ctx, inv.Token)
	if err != nil {
		return err
	}
	clientCert, err := enrolled.TLSCertificate()
	if err != nil {
		return err
	}

	fmt.Println("3. reusing the invitation is rejected")
	if _, err := api.Enroll(ctx, inv.Token); err == nil {
		return fmt.Errorf("security failure: invitation was reusable")
	} else {
		fmt.Printf("   rejected: %v\n", err)
	}

	serverCert, err := ca.IssueServerCert(pki.ServerNames{
		CommonName: "localhost", DNSNames: []string{"localhost"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}, 30*24*time.Hour)
	if err != nil {
		return err
	}
	gw, err := gateway.Start(gateway.Config{
		CA: ca, ServerCert: serverCert, ServiceName: "billing.internal",
	})
	if err != nil {
		return err
	}
	defer gw.Close()

	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)
	hc := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			RootCAs: pool, ServerName: "localhost", Certificates: []tls.Certificate{clientCert},
		}},
	}

	fmt.Println("4. client calls the mTLS gateway at " + gw.Addr())
	res, err := hc.Get("https://" + gw.Addr() + "/whoami")
	if err != nil {
		return err
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	fmt.Printf("   GET /whoami -> %d %s\n", res.StatusCode, body)
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("expected 200 from gateway, got %d", res.StatusCode)
	}

	fmt.Println("5. a certificate bound to analytics.internal is minted and rejected")
	other, err := api.CreateInvitation(ctx, "demo-admin", enroll.CreateInvitationInput{
		Service: "analytics.internal", Purpose: identity.PurposeAPI,
		InviteTTL: time.Minute, CertTTL: time.Hour,
	})
	if err != nil {
		return err
	}
	otherEnrolled, err := api.Enroll(ctx, other.Token)
	if err != nil {
		return err
	}
	otherCert, err := otherEnrolled.TLSCertificate()
	if err != nil {
		return err
	}
	otherClient := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			RootCAs: pool, ServerName: "localhost", Certificates: []tls.Certificate{otherCert},
		}},
	}
	if _, err := otherClient.Get("https://" + gw.Addr() + "/whoami"); err == nil {
		return fmt.Errorf("security failure: analytics certificate reached billing gateway")
	} else {
		fmt.Printf("   rejected at TLS layer: %v\n", err)
	}

	fmt.Println()
	fmt.Println("DEMO OK: one-time invitation, challenge, scoped certificate and mTLS enforcement all verified")
	return nil
}
