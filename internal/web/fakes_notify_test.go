package web

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/ctx42/testing/pkg/must"

	"github.com/chrobson/ramparteye/internal/model"
	"github.com/chrobson/ramparteye/internal/notify"
	"github.com/chrobson/ramparteye/internal/safety"
	"github.com/chrobson/ramparteye/internal/secret"
	"github.com/chrobson/ramparteye/internal/store"
)

// fakeNotifyStore is an in-memory notify.Store without runs: a test
// notification then carries no run summary.
type fakeNotifyStore struct {
	mu         sync.Mutex
	cfg        store.NotifyConfig
	deliveries []store.NotifyDelivery // oldest first
}

func (f *fakeNotifyStore) NotifyConfig(context.Context) (store.NotifyConfig, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.cfg, nil
}

func (f *fakeNotifyStore) SaveNotifyConfig(_ context.Context, c store.NotifyConfig) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case c.ClearURL:
		c.URLEnc, c.Endpoint = nil, ""
	case c.URLEnc == nil:
		c.URLEnc, c.Endpoint = f.cfg.URLEnc, f.cfg.Endpoint
	}
	switch {
	case c.ClearSecret:
		c.SecretEnc = nil
	case c.SecretEnc == nil:
		c.SecretEnc = f.cfg.SecretEnc
	}
	c.ClearURL, c.ClearSecret = false, false
	f.cfg = c
	return nil
}

func (f *fakeNotifyStore) RecordNotifyDelivery(_ context.Context, d store.NotifyDelivery) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	d.ID, d.At = int64(len(f.deliveries)+1), testNow
	f.deliveries = append(f.deliveries, d)
	return nil
}

func (f *fakeNotifyStore) NotifyDeliveries(_ context.Context, limit int) ([]store.NotifyDelivery, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []store.NotifyDelivery
	for i := len(f.deliveries) - 1; i >= 0 && len(out) < limit; i-- {
		out = append(out, f.deliveries[i])
	}
	return out, nil
}

func (f *fakeNotifyStore) Run(context.Context, int64) (store.RunSummary, error) {
	return store.RunSummary{}, store.ErrRunNotFound
}

func (f *fakeNotifyStore) ChangeRun(context.Context, int64) (store.ChangeRun, error) {
	return store.ChangeRun{}, store.ErrRunNotFound
}

func (f *fakeNotifyStore) Changes(context.Context, int64) ([]model.Change, error) { return nil, nil }

func (f *fakeNotifyStore) ExportServices(context.Context, int64) ([]store.ExportService, error) {
	return nil, nil
}

func (f *fakeNotifyStore) SafetyReceipt(context.Context, int64) (safety.Receipt, error) {
	return safety.Receipt{}, safety.ErrNoReceipt
}

func (f *fakeNotifyStore) HostStates(context.Context, model.HostStateKind) ([]model.HostState, error) {
	return nil, nil
}

func (f *fakeNotifyStore) AnnotationsByIPs(context.Context, []netip.Addr) (map[model.AssetKey]store.Annotation, error) {
	return nil, nil
}

func (f *fakeNotifyStore) LatestDoneRun(context.Context) (int64, error) { return 0, nil }

// hookReceiver is an httptest webhook endpoint answering with status.
type hookReceiver struct {
	srv    *httptest.Server
	mu     sync.Mutex
	status int
	bodies [][]byte
}

func (h *hookReceiver) count() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.bodies)
}

// url is the webhook URL; its path is the credential.
func (h *hookReceiver) url() string { return h.srv.URL + "/hooks/T0/SECRETPATH" }

// notifyEnv is a test server with a real notifier on a fake store and a
// webhook receiver.
type notifyEnv struct {
	*testEnv
	nst  *fakeNotifyStore
	hook *hookReceiver
}

func newNotifyEnv(t *testing.T) *notifyEnv {
	t.Helper()
	h := &hookReceiver{status: http.StatusNoContent}
	h.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		h.mu.Lock()
		h.bodies = append(h.bodies, b)
		status := h.status
		h.mu.Unlock()
		w.WriteHeader(status)
	}))
	t.Cleanup(h.srv.Close)
	nst := &fakeNotifyStore{cfg: store.NotifyConfig{Format: notify.FormatJSON, OnlyChanges: true}}
	box := must.Value(secret.NewBox([]byte("0123456789abcdef0123456789abcdef")))
	n := notify.New(nst, box, notify.Options{Instance: "test", Backoff: []time.Duration{0, 0},
		Log: slog.New(slog.DiscardHandler)})
	t.Cleanup(func() { _ = n.Close(context.Background()) })
	e := newEnv(t, func(d *Deps) { d.Notifier = n })
	return &notifyEnv{testEnv: e, nst: nst, hook: h}
}
