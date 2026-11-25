// Package gateway implements a mutual-TLS gateway that enforces offline
// (pinned CRL / OCSP) revocation checks on client certificates.
package gateway

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"offlinegw/internal/revoke"
)

// Config wires the gateway together.
type Config struct {
	// Certificates is the server certificate chain.
	Certificates []tls.Certificate
	// ClientCAs verifies client certificates.
	ClientCAs *x509.CertPool
	// Verifier performs the offline revocation check.
	Verifier *revoke.Verifier
	// Audit receives one record per connection attempt.
	Audit *revoke.AuditLogger
	// Handler serves an accepted connection. If nil, a banner handler is used.
	Handler func(conn net.Conn, degraded bool)
}

// Server accepts TLS connections and enforces revocation decisions.
type Server struct {
	cfg    Config
	tlsCfg *tls.Config
}

func NewServer(cfg Config) *Server {
	s := &Server{cfg: cfg}
	s.tlsCfg = &tls.Config{
		Certificates: cfg.Certificates,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    cfg.ClientCAs,
		MinVersion:   tls.VersionTLS12,
		VerifyConnection: func(state tls.ConnectionState) error {
			return s.verify(state)
		},
	}
	return s
}

// verify runs the offline revocation check after normal chain validation.
func (s *Server) verify(state tls.ConnectionState) error {
	if len(state.VerifiedChains) == 0 || len(state.VerifiedChains[0]) == 0 {
		return errors.New("gateway: no verified client certificate chain")
	}
	leaf := state.VerifiedChains[0][0]
	decision := s.cfg.Verifier.Check(leaf)
	if s.cfg.Audit != nil {
		s.cfg.Audit.Log("", leaf, decision, s.cfg.Verifier.StalePolicy)
	}
	if !decision.Allowed {
		return fmt.Errorf("gateway: client certificate rejected: %s", decision.Reason)
	}
	return nil
}

// Serve accepts connections on l until it is closed or ctx is cancelled.
func (s *Server) Serve(ctx context.Context, l net.Listener) error {
	go func() {
		<-ctx.Done()
		_ = l.Close()
	}()
	var wg sync.WaitGroup
	for {
		conn, err := l.Accept()
		if err != nil {
			wg.Wait()
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.handle(conn)
		}()
	}
}

func (s *Server) handle(raw net.Conn) {
	defer raw.Close()
	tlsConn, ok := raw.(*tls.Conn)
	if !ok {
		tlsConn = tls.Server(raw, s.tlsCfg)
	}
	_ = tlsConn.SetDeadline(time.Now().Add(30 * time.Second))
	if err := tlsConn.Handshake(); err != nil {
		return
	}
	leaf := tlsConn.ConnectionState().VerifiedChains[0][0]
	decision := s.cfg.Verifier.Check(leaf)
	handler := s.cfg.Handler
	if handler == nil {
		handler = bannerHandler
	}
	handler(tlsConn, decision.Degraded)
}

func bannerHandler(conn net.Conn, degraded bool) {
	mode := "full"
	if degraded {
		mode = "degraded"
	}
	fmt.Fprintf(conn, "OK mode=%s\n", mode)
}

// ListenAndServe is a convenience wrapper binding addr on TCP.
func (s *Server) ListenAndServe(ctx context.Context, addr string) error {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	return s.Serve(ctx, tls.NewListener(l, s.tlsCfg))
}
