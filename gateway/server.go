package gateway

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// ErrUnknownServerName is returned to crypto/tls when unknown_sni=reject.
var ErrUnknownServerName = errors.New("sni certificate routing: unknown server name; handshake disabled")

// ConnectionInfo describes a completed TLS handshake.
type ConnectionInfo struct {
	Conn       *tls.Conn
	Selection  Selection
	Generation uint64
	RemoteAddr net.Addr
}

// Handler runs after a TLS handshake succeeds.
type Handler func(ConnectionInfo)

// ServerOptions configures a Server.
type ServerOptions struct {
	Logger           *slog.Logger
	Handler          Handler
	HandshakeTimeout time.Duration
	// OnAccept runs after the connection's snapshot is captured and before
	// the handshake goroutine starts. It is useful for instrumentation.
	OnAccept func(net.Addr)
}

// Server is a TLS listener that selects certificates from a Store.
type Server struct {
	listener         net.Listener
	store            *Store
	logger           *slog.Logger
	handler          Handler
	handshakeTimeout time.Duration
	onAccept         func(net.Addr)

	serving  atomic.Bool
	closing  atomic.Bool
	closeErr error
	closeMu  sync.Mutex

	connMu sync.Mutex
	conns  map[net.Conn]struct{}
	wg     sync.WaitGroup
}

// Listen binds address and returns a Server.
func Listen(address string, store *Store, options ServerOptions) (*Server, error) {
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return nil, fmt.Errorf("listen on %q: %w", address, err)
	}
	server, err := NewServer(listener, store, options)
	if err != nil {
		listener.Close()
		return nil, err
	}
	return server, nil
}

// NewServer wraps an existing listener. The caller retains ownership of the
// listener only until Close is called.
func NewServer(listener net.Listener, store *Store, options ServerOptions) (*Server, error) {
	if listener == nil {
		return nil, fmt.Errorf("listener must not be nil")
	}
	if store == nil {
		return nil, fmt.Errorf("store must not be nil")
	}
	logger := options.Logger
	if logger == nil {
		logger = slog.Default()
	}
	timeout := options.HandshakeTimeout
	if timeout <= 0 {
		timeout = defaultHandshakeTimeout
	}
	return &Server{
		listener:         listener,
		store:            store,
		logger:           logger,
		handler:          options.Handler,
		handshakeTimeout: timeout,
		onAccept:         options.OnAccept,
		conns:            make(map[net.Conn]struct{}),
	}, nil
}

// Addr returns the listener address.
func (s *Server) Addr() net.Addr {
	return s.listener.Addr()
}

// Serve accepts connections until the context is canceled or the listener is
// closed. Each connection retains the snapshot current at accept time.
func (s *Server) Serve(ctx context.Context) error {
	if !s.serving.CompareAndSwap(false, true) {
		return fmt.Errorf("server is already serving")
	}
	defer s.serving.Store(false)

	stop := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			s.Close()
		case <-stop:
		}
	}()
	defer close(stop)

	for {
		raw, err := s.listener.Accept()
		if err != nil {
			if ctx.Err() != nil || s.closing.Load() || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("accept: %w", err)
		}

		snapshot := s.store.Current()
		if s.onAccept != nil {
			s.onAccept(raw.RemoteAddr())
		}
		if snapshot == nil {
			s.logger.Debug("closing connection without configuration",
				"remote_addr", addressString(raw.RemoteAddr()))
			raw.Close()
			continue
		}

		s.track(raw, true)
		s.wg.Add(1)
		go s.serveConn(ctx, raw, snapshot)
	}
}

func (s *Server) serveConn(ctx context.Context, raw net.Conn, snapshot *Snapshot) {
	defer s.wg.Done()
	defer s.track(raw, false)
	defer raw.Close()

	state := &selectionState{}
	tlsConfig := s.tlsConfigFor(raw.RemoteAddr(), snapshot, state)
	client := tls.Server(raw, tlsConfig)

	deadline := time.Now().Add(s.handshakeTimeout)
	_ = raw.SetDeadline(deadline)
	err := client.HandshakeContext(ctx)
	_ = raw.SetDeadline(time.Time{})
	if err != nil {
		s.logger.Debug("tls handshake failed",
			"remote_addr", addressString(raw.RemoteAddr()),
			"error", err)
		return
	}

	selection, ok := state.result()
	if !ok {
		s.logger.Debug("tls handshake completed without a routing decision",
			"remote_addr", addressString(raw.RemoteAddr()))
		return
	}
	if s.handler != nil {
		s.handler(ConnectionInfo{
			Conn:       client,
			Selection:  selection,
			Generation: snapshot.Generation(),
			RemoteAddr: raw.RemoteAddr(),
		})
	}
}

func (s *Server) tlsConfigFor(remote net.Addr, snapshot *Snapshot, state *selectionState) *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			selection := snapshot.Resolve(hello.ServerName)
			if state.decide(selection) {
				s.logSelection(remote, snapshot, selection)
			}
			selection, _ = state.result()
			if !selection.Selected() {
				return nil, ErrUnknownServerName
			}
			return &tls.Config{
				MinVersion:   tls.VersionTLS12,
				Certificates: []tls.Certificate{selection.Certificate.TLS},
			}, nil
		},
	}
}

func (s *Server) logSelection(remote net.Addr, snapshot *Snapshot, selection Selection) {
	attributes := []any{
		"remote_addr", addressString(remote),
		"sni", selection.ServerName,
		"result", string(selection.Kind),
		"reason", selection.Reason,
		"pattern", selection.Pattern,
		"certificate", selection.CertificateName,
		"config_generation", snapshot.Generation(),
	}
	if selection.Certificate != nil {
		attributes = append(attributes,
			"certificate_subject", selection.Certificate.Subject(),
			"certificate_sha256", selection.Certificate.FingerprintSHA256(),
		)
	}
	s.logger.Debug("sni certificate routing decision", attributes...)
}

func addressString(address net.Addr) string {
	if address == nil {
		return ""
	}
	return address.String()
}

// Wait waits for active connection goroutines to finish.
func (s *Server) Wait() {
	s.wg.Wait()
}

// Close stops accepting and closes all active connections.
func (s *Server) Close() error {
	s.closeMu.Lock()
	defer s.closeMu.Unlock()
	s.closing.Store(true)
	if s.listener != nil {
		s.closeErr = s.listener.Close()
	}
	s.connMu.Lock()
	for conn := range s.conns {
		_ = conn.Close()
	}
	s.connMu.Unlock()
	return s.closeErr
}

func (s *Server) track(conn net.Conn, add bool) {
	s.connMu.Lock()
	defer s.connMu.Unlock()
	if add {
		s.conns[conn] = struct{}{}
		return
	}
	delete(s.conns, conn)
}

type selectionState struct {
	mu        sync.Mutex
	decided   bool
	selection Selection
}

func (s *selectionState) decide(selection Selection) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.decided {
		return false
	}
	s.decided = true
	s.selection = selection
	return true
}

func (s *selectionState) result() (Selection, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.selection, s.decided
}
