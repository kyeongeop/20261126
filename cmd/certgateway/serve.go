package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"certgateway/enroll"
	"certgateway/gateway"
	"certgateway/invitation"
	"certgateway/pki"
)

func runServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	enrollAddr := fs.String("enroll-addr", "127.0.0.1:8080", "enrollment API listen address")
	gatewayAddr := fs.String("gateway-addr", "127.0.0.1:8443", "mTLS gateway listen address")
	service := fs.String("service", "billing.internal", "service name bound into client certificates")
	stateDir := fs.String("state-dir", "./certgateway-state", "directory receiving ca-cert.pem")
	adminToken := fs.String("admin-token", os.Getenv("CERTGATEWAY_ADMIN_TOKEN"), "admin bearer token (default: generated)")
	unified := fs.Bool("unified", false, "serve enrollment API and mTLS business routes on the TLS gateway port")
	if err := fs.Parse(args); err != nil {
		return err
	}

	ca, err := pki.NewRootCA("certgateway-local-ca", pki.DefaultCAValidity)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(*stateDir, 0o700); err != nil {
		return err
	}
	caPath := filepath.Join(*stateDir, "ca-cert.pem")
	if err := os.WriteFile(caPath, ca.CertPEM, 0o644); err != nil {
		return err
	}

	token := *adminToken
	if token == "" {
		raw := make([]byte, 24)
		if _, err := rand.Read(raw); err != nil {
			return err
		}
		token = hex.EncodeToString(raw)
	}

	store := invitation.NewStore()
	svc := enroll.NewService(store, ca)

	serverCert, err := ca.IssueServerCert(pki.ServerNames{
		CommonName:  "localhost",
		DNSNames:    []string{"localhost"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}, 90*24*time.Hour)
	if err != nil {
		return err
	}

	var apiSrv *http.Server
	var strictGW *gateway.Gateway
	var unifiedGW *gateway.UnifiedGateway
	if *unified {
		unifiedGW, err = gateway.StartUnified(gateway.UnifiedConfig{
			CA: ca, ServerCert: serverCert, ServiceName: *service, Addr: *gatewayAddr,
			EnrollHandler: accessLog(enroll.NewHandler(svc, token)),
		})
		if err != nil {
			return err
		}
		fmt.Printf("unified TLS:     https://%s (enrollment + mTLS business, service %q)\n", unifiedGW.Addr(), *service)
	} else {
		apiSrv = &http.Server{
			Addr:              *enrollAddr,
			Handler:           accessLog(enroll.NewHandler(svc, token)),
			ReadHeaderTimeout: 10 * time.Second,
		}
		go func() {
			fmt.Printf("enrollment API:  http://%s\n", *enrollAddr)
			if err := apiSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				fmt.Fprintf(os.Stderr, "enrollment server: %v\n", err)
			}
		}()
		strictGW, err = gateway.Start(gateway.Config{
			CA: ca, ServerCert: serverCert, ServiceName: *service, Addr: *gatewayAddr,
		})
		if err != nil {
			return err
		}
		fmt.Printf("mTLS gateway:    https://%s (service binding %q)\n", strictGW.Addr(), *service)
	}

	fmt.Printf("CA certificate:  %s\n", caPath)
	fmt.Printf("admin token:     %s\n", token)
	fmt.Println()
	if *unified {
		fmt.Println("create an invitation and enroll over the same TLS port:")
		fmt.Printf("  %s invite --api https://%s --cacert %s --admin-token %s --service %s --purpose api\n",
			os.Args[0], unifiedGW.Addr(), caPath, token, *service)
		fmt.Printf("  enroll --server https://%s --cacert %s --token <token>\n", unifiedGW.Addr(), caPath)
	} else {
		fmt.Println("create an invitation:")
		fmt.Printf("  %s invite --api http://%s --admin-token %s --service %s --purpose api\n",
			os.Args[0], *enrollAddr, token, *service)
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop
	fmt.Println("\nshutting down")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if strictGW != nil {
		_ = strictGW.Close()
	}
	if unifiedGW != nil {
		_ = unifiedGW.Close()
	}
	if apiSrv != nil {
		return apiSrv.Shutdown(ctx)
	}
	return nil
}

func accessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r)
		log.Printf("%s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)
	})
}

func runInvite(args []string) error {
	fs := flag.NewFlagSet("invite", flag.ContinueOnError)
	api := fs.String("api", "http://127.0.0.1:8080", "enrollment API base URL")
	adminToken := fs.String("admin-token", os.Getenv("CERTGATEWAY_ADMIN_TOKEN"), "admin bearer token")
	service := fs.String("service", "billing.internal", "service the certificate is restricted to")
	purpose := fs.String("purpose", "api", "purpose binding: api | metrics | admin")
	inviteTTL := fs.Duration("invite-ttl", 15*time.Minute, "how long the invitation can be used")
	certTTL := fs.Duration("cert-ttl", 24*time.Hour, "issued certificate lifetime")
	caCert := fs.String("cacert", "", "CA certificate PEM to trust for HTTPS API")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *adminToken == "" {
		return fmt.Errorf("--admin-token or CERTGATEWAY_ADMIN_TOKEN is required")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	httpClient := &http.Client{Timeout: 10 * time.Second}
	if *caCert != "" {
		pemBytes, err := os.ReadFile(*caCert)
		if err != nil {
			return err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pemBytes) {
			return fmt.Errorf("no certificate found in %s", *caCert)
		}
		httpClient.Transport = &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}
	}
	client := &enroll.Client{BaseURL: *api, HTTPClient: httpClient}
	inv, err := client.CreateInvitation(ctx, *adminToken, enroll.CreateInvitationInput{
		Service: *service, Purpose: *purpose, InviteTTL: *inviteTTL, CertTTL: *certTTL,
	})
	if err != nil {
		return err
	}
	fmt.Println("invitation created (token shown only once):")
	fmt.Printf("  id:      %s\n", inv.ID)
	fmt.Printf("  token:   %s\n", inv.Token)
	fmt.Printf("  service: %s\n", inv.Service)
	fmt.Printf("  purpose: %s\n", inv.Purpose)
	fmt.Printf("  expires: %s\n", inv.ExpiresAt.Format(time.RFC3339))
	fmt.Println()
	fmt.Printf("  enroll --server %s --token %s\n", *api, inv.Token)
	return nil
}
