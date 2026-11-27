package web

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/chrobson/ramparteye/internal/model"
	"github.com/chrobson/ramparteye/internal/safety"
	"github.com/chrobson/ramparteye/internal/store"
)

// fakeMonitor is a Monitor with fixed answers; an err field fails that query.
// A query blocks until its context ends when block is set.
type fakeMonitor struct {
	mu    sync.Mutex
	calls map[string]int
	block bool

	pingErr      error
	runCounts    map[string]int
	runCountsErr error
	lastScan     *store.FinishedScan
	lastScanErr  error
	hosts        map[model.HostStateKind]int
	hostsErr     error
	inventory    store.RunInventory
	inventoryErr error
	receiptRun   int64
	receiptRunEr error
	receipt      safety.Receipt
	receiptErr   error
}

func (f *fakeMonitor) enter(ctx context.Context, name string) error {
	f.mu.Lock()
	if f.calls == nil {
		f.calls = map[string]int{}
	}
	f.calls[name]++
	block := f.block
	f.mu.Unlock()
	if block {
		<-ctx.Done()
		return ctx.Err()
	}
	return nil
}

// count returns how many times a method was called.
func (f *fakeMonitor) count(name string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[name]
}

func (f *fakeMonitor) Ping(ctx context.Context) error {
	if err := f.enter(ctx, "Ping"); err != nil {
		return err
	}
	return f.pingErr
}

func (f *fakeMonitor) ScanRunCounts(ctx context.Context) (map[string]int, error) {
	if err := f.enter(ctx, "ScanRunCounts"); err != nil {
		return nil, err
	}
	return f.runCounts, f.runCountsErr
}

func (f *fakeMonitor) LastFinishedScan(ctx context.Context) (*store.FinishedScan, error) {
	if err := f.enter(ctx, "LastFinishedScan"); err != nil {
		return nil, err
	}
	return f.lastScan, f.lastScanErr
}

func (f *fakeMonitor) HostStateCounts(ctx context.Context) (map[model.HostStateKind]int, error) {
	if err := f.enter(ctx, "HostStateCounts"); err != nil {
		return nil, err
	}
	return f.hosts, f.hostsErr
}

func (f *fakeMonitor) LatestRunInventory(ctx context.Context) (store.RunInventory, error) {
	if err := f.enter(ctx, "LatestRunInventory"); err != nil {
		return store.RunInventory{}, err
	}
	return f.inventory, f.inventoryErr
}

func (f *fakeMonitor) LatestReceiptRun(ctx context.Context) (int64, error) {
	if err := f.enter(ctx, "LatestReceiptRun"); err != nil {
		return 0, err
	}
	return f.receiptRun, f.receiptRunEr
}

func (f *fakeMonitor) SafetyReceipt(ctx context.Context, runID int64) (safety.Receipt, error) {
	if err := f.enter(ctx, "SafetyReceipt"); err != nil {
		return safety.Receipt{}, err
	}
	return f.receipt, f.receiptErr
}

// metricsToken is the token of the test servers that serve /metrics.
const metricsToken = "test-metrics-token-0123456789"

// fakeClock is the clock of the metrics cache.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// monEnv is a test server with a fake monitor, the metrics endpoint
// enabled with metricsToken (unless an option removes it) and a log buffer.
type monEnv struct {
	*testEnv
	mon   *fakeMonitor
	logs  *bytes.Buffer
	clock *fakeClock
}

func newMonEnv(t *testing.T, m *fakeMonitor, opts ...envOpt) *monEnv {
	t.Helper()
	logs := &bytes.Buffer{}
	all := append([]envOpt{func(d *Deps) {
		d.Monitor = m
		d.Version = "v9.9.9-test"
		d.Cfg.MetricsToken = metricsToken
		d.Log = slog.New(slog.NewTextHandler(logs, nil))
	}}, opts...)
	e := &monEnv{testEnv: newEnv(t, all...), mon: m, logs: logs, clock: &fakeClock{t: testNow}}
	if e.srv.metrics != nil {
		e.srv.metrics.now = e.clock.now
	}
	return e
}

// withoutMetrics removes the metrics token.
func withoutMetrics() envOpt { return func(d *Deps) { d.Cfg.MetricsToken = "" } }

// getAuth sends GET path with an Authorization header (empty = none).
func (e *monEnv) getAuth(path, authorization string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	return rec
}

// scrape sends an authorised GET /metrics.
func (e *monEnv) scrape() *httptest.ResponseRecorder {
	return e.getAuth("/metrics", "Bearer "+metricsToken)
}

// advance moves the clock of the metrics cache.
func (e *monEnv) advance(d time.Duration) { e.clock.add(d) }
