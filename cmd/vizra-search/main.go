// Command vizra-search is the Vizra internal search service.
//
// At M0 it is a real service that answers honestly: the internal endpoints are
// HMAC-verified and return an explicit not_indexed status, and no
// search_schema_version is reported because this service owns no migrations
// yet (Q-001, ADR-002).
package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/yegamble/vizra-search/internal/buildinfo"
	"github.com/yegamble/vizra-search/internal/config"
	"github.com/yegamble/vizra-search/internal/httpapi"
)

func main() {
	if err := run(); err != nil {
		// The configuration error text names the offending variables but never
		// echoes their values.
		fmt.Fprintf(os.Stderr, "vizra-search: %v\n", err)
		os.Exit(1)
	}
}

// healthcheckTimeout bounds the self-probe so a wedged process cannot make the
// container healthcheck hang instead of failing.
const healthcheckTimeout = 3 * time.Second

// healthcheck calls this process's own /healthz. It reads the same
// VIZRA_SEARCH_ADDR the server binds, so a changed port cannot leave the
// healthcheck probing the wrong place.
func healthcheck() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	host, port, err := net.SplitHostPort(cfg.Addr)
	if err != nil {
		return fmt.Errorf("%s is not a host:port address: %w", config.EnvAddr, err)
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}

	ctx, cancel := context.WithTimeout(context.Background(), healthcheckTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"http://"+net.JoinHostPort(host, port)+"/healthz", nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("healthz: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("healthz returned %d", resp.StatusCode)
	}
	return nil
}

func run() error {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "version":
			fmt.Printf("%s %s (commit %s, built %s, %s)\n",
				buildinfo.Service, buildinfo.Version, buildinfo.Commit, buildinfo.BuildTime, buildinfo.GoVersion())
			return nil
		case "healthcheck":
			// The runtime image is `scratch`, so there is no shell and no curl
			// for a container healthcheck. The binary probes itself.
			return healthcheck()
		default:
			return fmt.Errorf("unknown command %q; known commands are version and healthcheck", os.Args[1])
		}
	}

	// Fail-secure boot: an invalid configuration — an empty key, the documented
	// development key in production mode, a short or placeholder key — stops
	// the process here, before anything listens.
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	log := httpapi.NewLogger(os.Stdout)
	srv := httpapi.New(cfg, log)

	httpServer := &http.Server{
		Addr:    cfg.Addr,
		Handler: srv.Handler(),
		// Bound every phase of a connection so a slow or idle peer cannot pin
		// a goroutine indefinitely.
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       cfg.RequestTimeout + 5*time.Second,
		WriteTimeout:      cfg.RequestTimeout + 5*time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}

	// Development mode is never a silent state: key validation is relaxed
	// there, and a developer who forgot which mode they are in must be able to
	// see it in the first lines of the log. The warning names the mode and what
	// it relaxes; it never contains the key.
	if !cfg.Mode.IsProduction() {
		log.Warn("running in development mode",
			"mode", string(cfg.Mode),
			"hmac_key_validation", "relaxed: the documented development key and short keys are accepted",
			"addr", cfg.Addr,
			"note", "never expose this process outside the loopback interface",
		)
		if cfg.ExceedsProductionCeilings() {
			log.Warn("configuration exceeds the limits a production process would refuse",
				"max_clock_skew", cfg.MaxClockSkew,
				"max_body_bytes", cfg.MaxBodyBytes,
				"note", "production refuses these values; the replay window and the pre-authentication memory bound are both widened here",
			)
		}
	}

	// The configuration is logged with the shared secret redacted.
	log.Info("starting", "config", cfg, "version", buildinfo.Version, "commit", buildinfo.Commit)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
			return
		}
		errCh <- nil
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
	}

	// Drain: readiness goes 503 while liveness stays 200, so an orchestrator
	// stops routing before the process stops accepting.
	log.Info("draining", "grace", cfg.ShutdownGrace)
	srv.BeginDrain()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownGrace)
	defer cancel()
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("shutdown: %w", err)
	}
	log.Info("stopped")
	return <-errCh
}
