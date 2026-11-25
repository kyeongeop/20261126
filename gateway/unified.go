package gateway

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"time"

	"certgateway/identity"
	"certgateway/pki"
)

// UnifiedConfig runs enrollment endpoints and protected business endpoints on
// a single TLS listener. Clients call the enrollment API over server-authenticated
// HTTPS *without* a client certificate; every other route requires a valid,
// CA-signed client certificate whose binding names ServiceName.
type UnifiedConfig struct {
	CA            *pki.CA
	ServerCert    tls.Certificate
	ServiceName   string
	Addr          string
	EnrollHandler http.Handler
	Business      http.Handler
}

// UnifiedGateway is the mixed-auth TLS gateway.
type UnifiedGateway struct {
	listener    net.Listener
	tlsListener net.Listener
	server      *http.Server
}

// StartUnified starts the unified gateway.
func StartUnified(cfg UnifiedConfig) (*UnifiedGateway, error) {
	if cfg.CA == nil {
		return nil, errors.New("gateway: CA is required")
	}
	if cfg.ServiceName == "" {
		return nil, errors.New("gateway: ServiceName is required")
	}
	if cfg.EnrollHandler == nil {
		return nil, errors.New("gateway: EnrollHandler is required")
	}
	addr := cfg.Addr
	if addr == "" {
		addr = "127.0.0.1:0"
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}

	pool := x509.NewCertPool()
	pool.AddCert(cfg.CA.Cert)
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cfg.ServerCert},
		// Enrollment callers have no certificate yet; verify any certificate
		// that is presented, and enforce presence/binding per protected route.
		ClientAuth: tls.VerifyClientCertIfGiven,
		ClientCAs:  pool,
		MinVersion: tls.VersionTLS12,
	}

	business := cfg.Business
	if business == nil {
		business = NewMux()
	}
	root := http.NewServeMux()
	root.Handle("/api/v1/", cfg.EnrollHandler)
	root.Handle("/healthz", cfg.EnrollHandler)
	root.Handle("/", RequireBoundClientCert(cfg.ServiceName)(business))

	g := &UnifiedGateway{
		listener:    ln,
		tlsListener: tls.NewListener(ln, tlsCfg),
		server:      &http.Server{Handler: root, ReadHeaderTimeout: 10 * time.Second},
	}
	go g.server.Serve(g.tlsListener)
	return g, nil
}

// Addr is the TCP address of the unified listener.
func (g *UnifiedGateway) Addr() string { return g.listener.Addr().String() }

// Close gracefully shuts the gateway down.
func (g *UnifiedGateway) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return g.server.Shutdown(ctx)
}

// RequireBoundClientCert is route-level mTLS enforcement for the unified
// gateway: it requires a peer certificate and an identity binding equal to
// service. Purpose checks remain the business handler's responsibility.
func RequireBoundClientCert(service string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
				writeError(w, http.StatusUnauthorized, "client certificate required")
				return
			}
			if _, err := identity.Check(r.TLS.PeerCertificates[0], service, ""); err != nil {
				writeError(w, http.StatusForbidden, err.Error())
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
