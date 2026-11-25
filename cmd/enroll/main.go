// Command enroll performs one-time-invitation client-certificate
// self-registration against a running certgateway enrollment API.
//
//	enroll --server http://127.0.0.1:8080 --token <one-time-token> --out ./creds
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"certgateway/enroll"
)

func main() {
	server := flag.String("server", "http://127.0.0.1:8080", "enrollment API base URL")
	token := flag.String("token", "", "one-time invitation token (required)")
	outDir := flag.String("out", "./client-creds", "directory for client.key and client.pem")
	caCert := flag.String("cacert", "", "CA certificate PEM to trust for HTTPS enrollment")
	timeout := flag.Duration("timeout", 15*time.Second, "request timeout")
	flag.Parse()

	if *token == "" {
		fmt.Fprintln(os.Stderr, "error: --token is required")
		flag.Usage()
		os.Exit(2)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	httpClient := &http.Client{Timeout: *timeout}
	if *caCert != "" {
		pemBytes, err := os.ReadFile(*caCert)
		if err != nil {
			fatal(err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pemBytes) {
			fatal(fmt.Errorf("no certificate found in %s", *caCert))
		}
		httpClient.Transport = &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}
	}

	client := &enroll.Client{BaseURL: *server, HTTPClient: httpClient}
	enrolled, err := client.Enroll(ctx, *token)
	if err != nil {
		fmt.Fprintf(os.Stderr, "enrollment failed: %v\n", err)
		os.Exit(1)
	}

	if err := os.MkdirAll(*outDir, 0o700); err != nil {
		fatal(err)
	}
	keyPath := filepath.Join(*outDir, "client.key")
	certPath := filepath.Join(*outDir, "client.pem")
	if err := os.WriteFile(keyPath, enrolled.KeyPEM, 0o600); err != nil {
		fatal(err)
	}
	if err := os.WriteFile(certPath, enrolled.ChainPEM, 0o644); err != nil {
		fatal(err)
	}

	fmt.Println("enrollment succeeded")
	fmt.Printf("  private key: %s\n", keyPath)
	fmt.Printf("  certificate: %s\n", certPath)
	fmt.Println("use it against the TLS gateway, for example:")
	fmt.Printf("  curl --cacert ca-cert.pem --cert %s --key %s https://127.0.0.1:8443/whoami\n",
		certPath, keyPath)
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "error: %v\n", err)
	os.Exit(1)
}
