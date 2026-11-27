package web

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/chrobson/ramparteye/internal/model"
	"github.com/chrobson/ramparteye/internal/safety"
	"github.com/chrobson/ramparteye/internal/store"
)

// Monitor is what GET /healthz and GET /metrics need from storage;
// *store.Store satisfies it. Every method returns aggregates only.
type Monitor interface {
	Ping(ctx context.Context) error
	ScanRunCounts(ctx context.Context) (map[string]int, error)
	LastFinishedScan(ctx context.Context) (*store.FinishedScan, error)
	HostStateCounts(ctx context.Context) (map[model.HostStateKind]int, error)
	LatestRunInventory(ctx context.Context) (store.RunInventory, error)
	LatestReceiptRun(ctx context.Context) (int64, error)
	SafetyReceipt(ctx context.Context, runID int64) (safety.Receipt, error)
}

// healthTimeout bounds the database query of /healthz.
const healthTimeout = 2 * time.Second

var errNoMonitor = errors.New("no database monitor configured")

// initMonitoring prepares /healthz and, when a token is configured,
// /metrics.
func (s *Server) initMonitoring() error {
	s.monitor, s.healthTimeout = s.d.Monitor, healthTimeout
	if tok := s.d.Cfg.MetricsToken; tok != "" {
		if s.monitor == nil {
			return errors.New("web: Deps.Monitor is required when a metrics token is set")
		}
		s.metrics = newMetricsCollector(s, tok)
	}
	return nil
}

// monitoringRoutes adds the endpoints that need no session: /healthz, and
// /metrics when it is enabled (without a token the path is an unknown one).
func (s *Server) monitoringRoutes(r chi.Router) {
	r.Get("/healthz", s.healthz)
	r.Head("/healthz", s.healthz)
	if s.metrics != nil {
		r.Get("/metrics", s.metricsHandler)
	}
}

// healthz answers 200 "ok" while the process serves and the database
// answers a trivial query within healthTimeout, 503 otherwise. It needs no
// session and says nothing about why it failed: the cause is logged.
func (s *Server) healthz(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Content-Type", "text/plain; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	if err := s.ping(r.Context()); err != nil {
		s.log.Error("healthz: database check failed", "err", err)
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("unavailable"))
		return
	}
	_, _ = w.Write([]byte("ok"))
}

func (s *Server) ping(ctx context.Context) error {
	if s.monitor == nil {
		return errNoMonitor
	}
	ctx, cancel := context.WithTimeout(ctx, s.healthTimeout)
	defer cancel()
	return s.monitor.Ping(ctx)
}
