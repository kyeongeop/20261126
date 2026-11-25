// Package gateway implements the local mTLS TLS gateway.
//
// It is assembled directly from net and crypto/tls: a net.Listener is
// upgraded with tls.NewListener using RequireAndVerifyClientCert, and a
// VerifyConnection hook enforces that the client certificate's signed
// identity binding names the service this gateway serves. Route handlers then
// enforce the bound purpose.
package gateway

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"certgateway/identity"
	"certgateway/pki"
)

// Config configures a Gateway.
type Config struct {
	// CA is the trusted client-certificate authority.
	CA *pki.CA
	// ServerCert is this gateway's TLS server certificate.
	ServerCert tls.Certificate
	// ServiceName is the only service binding accepted at the TLS layer.
	ServiceName string
	// Handler serves HTTP traffic after mTLS and binding checks. When nil,
	// NewMux is used.
	Handler http.Handler
	// Addr defaults to 127.0.0.1:0 (random loopback port).
	Addr string
}

// Gateway is a running TLS-terminating HTTP gateway.
type Gateway struct {
	serviceName string
	listener    net.Listener
	tlsListener net.Listener
	server      *http.Server
	tlsConfig   *tls.Config
}

// Start binds Addr and starts serving in a background goroutine.
func Start(cfg Config) (*Gateway, error) {
	if cfg.CA == nil {
		return nil, errors.New("gateway: CA is required")
	}
	if cfg.ServiceName == "" {
		return nil, errors.New("gateway: ServiceName is required")
	}
	addr := cfg.Addr
	if addr == "" {
		addr = "127.0.0.1:0"
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("gateway: listen %s: %w", addr, err)
	}

	clientCAs := x509.NewCertPool()
	clientCAs.AddCert(cfg.CA.Cert)

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cfg.ServerCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAs,
		MinVersion:   tls.VersionTLS12,
		VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 {
				return errors.New("gateway: client presented no certificate")
			}
			_, err := identity.Check(state.PeerCertificates[0], cfg.ServiceName, "")
			if err != nil {
				return fmt.Errorf("gateway: rejected client certificate: %w", err)
			}
			return nil
		},
	}

	handler := cfg.Handler
	if handler == nil {
		handler = NewMux()
	}
	g := &Gateway{
		serviceName: cfg.ServiceName,
		listener:    ln,
		tlsListener: tls.NewListener(ln, tlsCfg),
		tlsConfig:   tlsCfg,
		server: &http.Server{
			Handler:           handler,
			ReadHeaderTimeout: 10 * time.Second,
		},
	}

	go func() {
		_ = g.server.Serve(g.tlsListener)
	}()
	return g, nil
}

// Addr is the actual TCP address of the listener.
func (g *Gateway) Addr() string { return g.listener.Addr().String() }

// ServiceName returns the bound service name.
func (g *Gateway) ServiceName() string { return g.serviceName }

// TLSConfig returns a clone of the gateway TLS config (mainly for inspection).
func (g *Gateway) TLSConfig() *tls.Config { return g.tlsConfig.Clone() }

// Close stops the HTTP server and closes the listener.
func (g *Gateway) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return g.server.Shutdown(ctx)
}
