// Command gateway runs a mutual-TLS gateway with offline revocation checks
// backed by pinned CRL files and/or pinned OCSP responses.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"offlinegw/internal/gateway"
	"offlinegw/internal/revoke"
)

func main() {
	var (
		addr        = flag.String("addr", "127.0.0.1:8443", "listen address")
		certFile    = flag.String("cert", "", "server certificate (PEM)")
		keyFile     = flag.String("key", "", "server private key (PEM)")
		caFile      = flag.String("ca", "", "client CA bundle (PEM)")
		crlFiles    = flag.String("crl", "", "comma-separated pinned CRL files")
		ocspFiles   = flag.String("ocsp", "", "comma-separated pinned OCSP response files")
		stalePolicy = flag.String("stale-policy", "deny", "policy for expired revocation data: deny|allow|degrade")
		auditFile   = flag.String("audit", "", "audit log file (default stderr)")
	)
	flag.Parse()

	if *certFile == "" || *keyFile == "" || *caFile == "" {
		log.Fatal("required flags: -cert, -key, -ca")
	}
	policy, err := revoke.ParseStalePolicy(*stalePolicy)
	if err != nil {
		log.Fatal(err)
	}
	serverCert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
	if err != nil {
		log.Fatalf("load server certificate: %v", err)
	}
	caPEM, err := os.ReadFile(*caFile)
	if err != nil {
		log.Fatalf("read CA bundle: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		log.Fatal("no CA certificates found in -ca bundle")
	}

	source := &revoke.Source{}
	// Load pinned revocation material against every CA in the bundle.
	caCerts, err := parseCACerts(caPEM)
	if err != nil {
		log.Fatal(err)
	}
	for _, path := range splitNonEmpty(*crlFiles) {
		loaded := false
		for _, ca := range caCerts {
			if err := source.LoadCRLFile(path, ca); err == nil {
				loaded = true
				break
			}
		}
		if !loaded {
			log.Fatalf("CRL %s did not verify against any CA", path)
		}
	}
	for _, path := range splitNonEmpty(*ocspFiles) {
		loaded := false
		for _, ca := range caCerts {
			if err := source.LoadOCSPFile(path, ca); err == nil {
				loaded = true
				break
			}
		}
		if !loaded {
			log.Fatalf("OCSP response %s did not verify against any CA", path)
		}
	}

	auditOut := os.Stderr
	if *auditFile != "" {
		f, err := os.OpenFile(*auditFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			log.Fatalf("open audit log: %v", err)
		}
		defer f.Close()
		auditOut = f
	}

	srv := gateway.NewServer(gateway.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    pool,
		Verifier:     &revoke.Verifier{Source: source, StalePolicy: policy},
		Audit:        revoke.NewAuditLogger(auditOut),
	})

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	log.Printf("gateway listening on %s (stale-policy=%s)", *addr, policy)
	if err := srv.ListenAndServe(ctx, *addr); err != nil {
		log.Fatal(err)
	}
}

func splitNonEmpty(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}

func parseCACerts(pemData []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for {
		var block *pem.Block
		block, pemData = pem.Decode(pemData)
		if block == nil {
			break
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse CA certificate: %w", err)
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates in CA bundle")
	}
	return certs, nil
}
