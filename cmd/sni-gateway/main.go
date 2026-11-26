package main

import (
	"context"
	"crypto/sha256"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/kyeongeop/sni-gateway/gateway"
)

func main() {
	configPath := flag.String("config", filepath.Join("config", "gateway.json"), "path to gateway JSON configuration")
	checkOnly := flag.Bool("check", false, "validate configuration and exit")
	watch := flag.Bool("watch", true, "poll the configuration file for changes")
	watchInterval := flag.Duration("watch-interval", 2*time.Second, "configuration polling interval")
	flag.Parse()

	level := new(slog.LevelVar)
	level.Set(slog.LevelInfo)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	runtime, err := gateway.LoadConfig(*configPath)
	if err != nil {
		logger.Error("failed to load configuration", "error", err)
		os.Exit(1)
	}
	level.Set(runtime.LogLevel)

	if *checkOnly {
		fmt.Printf("configuration valid: listen=%s unknown_sni=%s routes_loaded=true\n",
			runtime.ListenAddress, runtime.Snapshot.UnknownPolicy())
		return
	}
	if *watch && *watchInterval <= 0 {
		logger.Error("watch-interval must be positive")
		os.Exit(1)
	}

	store := gateway.NewStore(runtime.Snapshot)
	server, err := gateway.Listen(runtime.ListenAddress, store, gateway.ServerOptions{
		Logger:           logger,
		Handler:          writeConnectionInfo,
		HandshakeTimeout: runtime.HandshakeTimeout,
	})
	if err != nil {
		logger.Error("failed to start TLS listener", "error", err)
		os.Exit(1)
	}

	reloader := &configReloader{
		path:          runtime.ConfigPath,
		store:         store,
		logger:        logger,
		level:         level,
		listenAddress: runtime.ListenAddress,
		lastHash:      runtime.ConfigSHA256,
		haveHash:      true,
	}

	signalCtx, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()
	ctx, cancel := context.WithCancel(signalCtx)
	defer cancel()

	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)

	var ticks <-chan time.Time
	if *watch {
		ticker := time.NewTicker(*watchInterval)
		defer ticker.Stop()
		ticks = ticker.C
	}

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-hup:
				reloader.reload(true)
			case <-ticks:
				reloader.reload(false)
			}
		}
	}()

	logger.Info("TLS gateway listening",
		"address", server.Addr().String(),
		"config", runtime.ConfigPath,
		"generation", store.Current().Generation(),
		"unknown_sni", runtime.Snapshot.UnknownPolicy())

	serveDone := make(chan error, 1)
	go func() {
		serveDone <- server.Serve(ctx)
	}()

	var serveErr error
	select {
	case <-ctx.Done():
	case serveErr = <-serveDone:
	}
	cancel()
	_ = server.Close()
	server.Wait()

	if serveErr != nil {
		logger.Error("TLS gateway stopped with an error", "error", serveErr)
		os.Exit(1)
	}
	logger.Info("TLS gateway stopped")
}

type configReloader struct {
	path          string
	store         *gateway.Store
	logger        *slog.Logger
	level         *slog.LevelVar
	listenAddress string
	lastHash      [sha256.Size]byte
	haveHash      bool
}

func (r *configReloader) reload(force bool) {
	if !force {
		hash, err := hashFile(r.path)
		if err != nil {
			r.logger.Warn("configuration file stat failed", "path", r.path, "error", err)
			return
		}
		if r.haveHash && hash == r.lastHash {
			return
		}
	}

	runtime, err := gateway.LoadConfig(r.path)
	if err != nil {
		r.haveHash = false
		r.logger.Error("configuration reload failed; keeping previous snapshot",
			"path", r.path, "error", err)
		return
	}
	r.lastHash = runtime.ConfigSHA256
	r.haveHash = true
	generation := r.store.Set(runtime.Snapshot)
	r.level.Set(runtime.LogLevel)

	attributes := []any{
		"path", runtime.ConfigPath,
		"generation", generation,
		"unknown_sni", runtime.Snapshot.UnknownPolicy(),
	}
	if runtime.ListenAddress != r.listenAddress {
		attributes = append(attributes,
			"listen_address", runtime.ListenAddress,
			"note", "listen_address changes require a restart")
	}
	r.logger.Info("configuration reloaded", attributes...)
}

func hashFile(path string) ([sha256.Size]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	return sha256.Sum256(data), nil
}

func writeConnectionInfo(info gateway.ConnectionInfo) {
	defer info.Conn.Close()
	body := fmt.Sprintf(
		"sni=%s\nresult=%s\nreason=%s\npattern=%s\ncertificate=%s\nconfig_generation=%d\n",
		info.Selection.ServerName,
		info.Selection.Kind,
		info.Selection.Reason,
		info.Selection.Pattern,
		info.Selection.CertificateName,
		info.Generation,
	)
	_, _ = fmt.Fprintf(info.Conn,
		"HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		len(body), body)
}
