package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/chrobson/ramparteye/internal/bootstrap"
	"github.com/chrobson/ramparteye/internal/config"
	"github.com/chrobson/ramparteye/internal/db"
	"github.com/chrobson/ramparteye/internal/target"
	"github.com/chrobson/ramparteye/internal/web"
)

const (
	// defaultProfileName is the manual profile covering every target that
	// a fresh database gets, so "Scan now" works right after adding targets.
	defaultProfileName = "All targets"
	// shutdownTimeout bounds each graceful shutdown step.
	shutdownTimeout = 15 * time.Second
)

func cmdServe(e *env, args []string) int {
	if len(args) > 0 {
		return e.fail("serve", usageError("usage: ramparteye serve"))
	}
	cfg, code := e.config()
	if code != exitOK {
		return code
	}
	if err := serve(e, cfg, e.logger()); err != nil {
		return e.fail("serve", err)
	}
	return exitOK
}

// serve runs the web UI, the scheduler and the DefectDojo pusher until
// e.ctx is done, then shuts down: scans pause, the HTTP server drains,
// the runner stops and the pusher closes, in that order.
func serve(e *env, cfg config.Config, log *slog.Logger) error {
	ctx := e.ctx
	box, created, err := loadBox(&cfg)
	if err != nil {
		return err
	}
	if created {
		log.Info("generated secret key", "dir", cfg.SecretsDir)
	}
	sc, err := buildScope(ctx, cfg, config.DefaultResolver)
	if err != nil {
		return err
	}
	if sc.Empty() {
		log.Warn("no scan scope configured: every scan and import is refused; set RAMPART_ALLOWED_CIDRS")
	}

	pool, st, err := openStore(ctx, cfg)
	if err != nil {
		return err
	}
	defer pool.Close()
	applied, err := db.Migrate(ctx, pool)
	if err != nil {
		return err
	}
	if len(applied) > 0 {
		log.Info("migrations applied", "versions", applied)
	}
	if _, err := bootstrap.Ensure(ctx, st, cfg, e.stdout); err != nil {
		return err
	}
	if _, err := st.EnsureDefaultScanConfig(ctx, defaultProfileName); err != nil {
		return fmt.Errorf("default scan profile: %w", err)
	}

	s := newScanner(cfg, st, sc, box, log)
	// Recover returns chunks left running by a previous process to pending,
	// syncs the built-in signatures and loads the enabled ones.
	if err := s.runner.Recover(ctx); err != nil {
		return err
	}

	// runCtx outlives the request that starts a scan and ends at shutdown:
	// scans, SSE streams and request contexts all stop with it.
	runCtx, stopRuns := context.WithCancel(context.WithoutCancel(ctx))
	defer stopRuns()
	h, err := web.NewServer(web.Deps{
		Store:       st,
		Runner:      s.runner,
		Pusher:      s.pusher,
		Exchange:    web.NewExchange(pool),
		Scope:       sc,
		Cfg:         cfg,
		Log:         log,
		Resolver:    target.Resolver(config.DefaultResolver),
		ShutdownCtx: runCtx,
		Box:         box,
		SignaturesChanged: func() {
			rctx, cancel := context.WithTimeout(runCtx, 30*time.Second)
			defer cancel()
			s.reloadSignatures(rctx)
		},
	})
	if err != nil {
		return err
	}

	ln, err := net.Listen("tcp", cfg.HTTPAddr)
	if err != nil {
		return err
	}
	srv := newHTTPServer(h.Handler(), runCtx, log)
	loopDone := make(chan struct{})
	go func() {
		defer close(loopDone)
		tickLoop(runCtx, s.runner, cfg.TickEvery, time.Now)
	}()
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(ln) }()
	log.Info("listening", "addr", ln.Addr().String(), "scope", sc.Allowed(), "exclude", sc.Excluded())
	if e.onListen != nil {
		e.onListen(ln.Addr().String())
	}

	select {
	case <-ctx.Done():
		log.Info("shutting down")
	case err = <-serveErr:
	}
	stopRuns()
	sctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if serr := srv.Shutdown(sctx); serr != nil {
		log.Warn("HTTP shutdown", "err", serr)
	}
	<-loopDone
	s.stop(shutdownTimeout)
	if errors.Is(err, http.ErrServerClosed) {
		err = nil
	}
	return err
}

// newHTTPServer returns the UI server. There is no write timeout: the
// /events SSE stream stays open; base is cancelled at shutdown.
func newHTTPServer(h http.Handler, base context.Context, log *slog.Logger) *http.Server {
	srv := &http.Server{
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
		BaseContext:       func(net.Listener) context.Context { return base },
	}
	if log != nil {
		srv.ErrorLog = slog.NewLogLogger(log.Handler(), slog.LevelWarn)
	}
	return srv
}

// ticker is one scheduler step; *runner.Runner satisfies it.
type ticker interface {
	Tick(ctx context.Context, now time.Time)
}

// tickLoop calls Tick at once and then every interval until ctx is done.
func tickLoop(ctx context.Context, r ticker, every time.Duration, now func() time.Time) {
	if every <= 0 {
		every = time.Minute
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		r.Tick(ctx, now())
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
