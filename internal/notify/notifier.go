// Package notify posts a summary of a finished scan run to a webhook the
// administrator configured: a generic JSON receiver (versioned Message,
// optionally HMAC-signed) or a Slack-compatible incoming webhook (Slack,
// Mattermost, Rocket.Chat). The webhook URL and the signing secret are
// credentials: they are stored sealed, never shown, and kept out of errors,
// logs and the delivery history, which names at most scheme and host.
//
// The notifier talks only to that configured endpoint. It is not part of
// scanning: it does not use the scanner's HTTP prober and is not counted in
// the safety receipt.
package notify

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"github.com/chrobson/ramparteye/internal/model"
	"github.com/chrobson/ramparteye/internal/safety"
	"github.com/chrobson/ramparteye/internal/secret"
	"github.com/chrobson/ramparteye/internal/store"
)

// Delivery triggers recorded in the history.
const (
	TriggerAuto = "auto"
	TriggerTest = "test"
)

const (
	// DefaultTimeout bounds one delivery, retries included.
	DefaultTimeout = time.Minute
	// recordTimeout bounds writing the history row, which happens even when
	// the delivery ran out of time or was cancelled.
	recordTimeout = 10 * time.Second
	panicMessage  = "internal error: notification panicked"
)

// ErrClosed is returned by SendTest after Close. Nothing is recorded.
var ErrClosed = errors.New("notifier is closed")

// Store is the persistence the notifier needs; *store.Store satisfies it.
type Store interface {
	SettingsStore
	RecordNotifyDelivery(ctx context.Context, d store.NotifyDelivery) error
	NotifyDeliveries(ctx context.Context, limit int) ([]store.NotifyDelivery, error)
	Run(ctx context.Context, id int64) (store.RunSummary, error)
	ChangeRun(ctx context.Context, runID int64) (store.ChangeRun, error)
	Changes(ctx context.Context, runID int64) ([]model.Change, error)
	ExportServices(ctx context.Context, runID int64) ([]store.ExportService, error)
	SafetyReceipt(ctx context.Context, runID int64) (safety.Receipt, error)
	HostStates(ctx context.Context, state model.HostStateKind) ([]model.HostState, error)
	AnnotationsByIPs(ctx context.Context, ips []netip.Addr) (map[model.AssetKey]store.Annotation, error)
	LatestDoneRun(ctx context.Context) (int64, error)
}

var _ Store = (*store.Store)(nil)

// Options configure a Notifier. Zero values select the defaults.
type Options struct {
	// Instance is the installation id put into every message.
	Instance string
	// UserAgent of the webhook requests.
	UserAgent string
	// Log receives delivery failures (slog.Default when nil). Lines carry
	// the run, the endpoint (scheme and host) and the sanitised error.
	Log *slog.Logger
	// HTTPClient replaces the default verified-TLS client; it is copied
	// and never follows redirects.
	HTTPClient *http.Client
	// Backoff is the wait before each retry (2 s, 8 s when nil).
	Backoff []time.Duration
	// AttemptTimeout bounds one HTTP attempt (DefaultAttemptTimeout).
	AttemptTimeout time.Duration
	// Timeout bounds one delivery with its retries (DefaultTimeout).
	Timeout time.Duration
	// Now is the clock (time.Now when nil).
	Now func() time.Time
}

// Delivery is the outcome of one delivery.
type Delivery struct {
	RunID    int64 // 0 for a test
	Event    string
	Trigger  string
	Endpoint string
	Attempts int
	Status   int // last HTTP status, 0 = no response
	OK       bool
	Error    string
}

// Notifier delivers run summaries and records every delivery.
//
// Shutdown order: stop the runner first (no more OnRunDone calls), then
// call Close, which cancels deliveries in flight (each still records its
// row) and waits for them.
type Notifier struct {
	st  Store
	box *secret.Box
	opt Options
	hc  *http.Client

	base   context.Context // cancelled by Close
	cancel context.CancelFunc

	mu     sync.Mutex
	closed bool
	wg     sync.WaitGroup
}

// New returns a notifier for the settings in st; box opens the sealed
// webhook URL and secret.
func New(st Store, box *secret.Box, opt Options) *Notifier {
	base, cancel := context.WithCancel(context.Background())
	return &Notifier{st: st, box: box, opt: opt, hc: newHTTPClient(opt.HTTPClient), base: base, cancel: cancel}
}

// Settings returns the stored settings without credentials.
func (n *Notifier) Settings(ctx context.Context) (Settings, error) { return LoadSettings(ctx, n.st) }

// SaveSettings validates and stores s (see SaveSettings).
func (n *Notifier) SaveSettings(ctx context.Context, s Settings) error {
	return SaveSettings(ctx, n.st, n.box, s)
}

// Deliveries returns the latest deliveries, newest first.
func (n *Notifier) Deliveries(ctx context.Context, limit int) ([]store.NotifyDelivery, error) {
	return n.st.NotifyDeliveries(ctx, limit)
}

// OnRunDone is the runner hook. A run that ended "done" is notified (when
// it has changes, unless "only when something changed" is off), one that
// ended "failed" only when that is enabled; any other status is ignored,
// as is every call after Close. It never blocks the runner, never panics
// into it and never reports an error to it: failures land in the history.
// Settings that cannot be loaded at all are only logged.
func (n *Notifier) OnRunDone(ctx context.Context, runID int64, status string) {
	var event string
	switch status {
	case store.RunDone:
		event = EventFinished
	case store.RunFailed:
		event = EventFailed
	default:
		return
	}
	done, err := n.begin()
	if err != nil {
		n.log().Warn("webhook notification dropped: notifier closed", "run", runID)
		return
	}
	go func() {
		defer done()
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), n.timeout())
		defer cancel()
		ctx, stop := n.withBase(ctx)
		defer stop()
		defer n.recoverDelivery(ctx, runID, event)

		s, err := LoadSettings(ctx, n.st)
		switch {
		case err != nil:
			n.log().Warn("webhook notification: settings unavailable", "run", runID, "err", err)
			return
		case !s.Enabled || !s.URLSet, event == EventFailed && !s.NotifyFailed:
			return
		}
		d, err := n.load(ctx, runID)
		if err != nil {
			n.finish(ctx, Delivery{RunID: runID, Event: event, Trigger: TriggerAuto, Endpoint: s.Endpoint,
				Error: clean(fmt.Sprintf("load run %d: %v", runID, err), maxErrorText)})
			return
		}
		if event == EventFinished && s.OnlyChanges && len(d.Changes) == 0 {
			return
		}
		n.deliver(ctx, s, TriggerAuto, event, d)
	}()
}

// SendTest sends a test message with the stored settings (enabled or not),
// describing the latest finished run when there is one, and records it. It
// returns ErrNotConfigured without a webhook URL and the delivery error
// (the recorded text) when the delivery failed.
func (n *Notifier) SendTest(ctx context.Context) (Delivery, error) {
	done, err := n.begin()
	if err != nil {
		return Delivery{}, err
	}
	defer done()
	ctx, stop := n.withBase(ctx)
	defer stop()
	s, err := LoadSettings(ctx, n.st)
	if err != nil {
		return Delivery{}, err
	}
	if !s.URLSet {
		return Delivery{}, ErrNotConfigured
	}
	var d *runData
	if id, err := n.st.LatestDoneRun(ctx); err == nil && id != 0 {
		if d, err = n.load(ctx, id); err != nil {
			n.log().Warn("webhook test: latest run unavailable", "run", id, "err", err)
			d = nil
		}
	}
	res := n.deliver(ctx, s, TriggerTest, EventTest, d)
	if !res.OK {
		return res, errors.New(res.Error)
	}
	return res, nil
}

// deliver builds the message, posts it and records the delivery.
func (n *Notifier) deliver(ctx context.Context, s Settings, trigger, event string, d *runData) Delivery {
	res := Delivery{Event: event, Trigger: trigger, Endpoint: s.Endpoint}
	if d != nil && trigger == TriggerAuto {
		res.RunID = d.Run.ID
	}
	t, err := loadTarget(ctx, n.st, n.box)
	if err != nil {
		res.Error = clean(err.Error(), maxErrorText)
		return n.finish(ctx, res)
	}
	now := n.now()
	m := buildMessage(event, now, n.opt.Instance, s.BaseURL, d)
	var body []byte
	if s.Format == FormatSlack {
		body, err = m.Slack()
	} else {
		body, err = m.JSON()
	}
	if err != nil {
		res.Error = "encode message: " + clean(err.Error(), maxErrorText)
		return n.finish(ctx, res)
	}
	r := n.post(ctx, t, event, body, now)
	res.Attempts, res.Status, res.OK = r.attempts, r.status, r.err == nil
	if r.err != nil {
		res.Error = r.err.Error()
	}
	return n.finish(ctx, res)
}

// finish records res and logs a failure.
func (n *Notifier) finish(ctx context.Context, res Delivery) Delivery {
	if !res.OK {
		n.log().Warn("webhook notification failed", "run", res.RunID, "trigger", res.Trigger,
			"endpoint", res.Endpoint, "err", res.Error)
	}
	row := store.NotifyDelivery{Trigger: res.Trigger, Event: res.Event, Endpoint: res.Endpoint,
		Attempts: res.Attempts, OK: res.OK, Error: res.Error}
	if res.RunID != 0 {
		id := res.RunID
		row.RunID = &id
	}
	if res.Status != 0 {
		st := res.Status
		row.Status = &st
	}
	if err := n.record(ctx, row); err != nil {
		n.log().Error("webhook notification: recording failed", "run", res.RunID, "err", err)
	}
	return res
}

// load reads what a message says about run runID.
func (n *Notifier) load(ctx context.Context, runID int64) (*runData, error) {
	run, err := n.st.Run(ctx, runID)
	if err != nil {
		return nil, err
	}
	d := &runData{Run: run}
	cr, err := n.st.ChangeRun(ctx, runID)
	if err != nil {
		return nil, err
	}
	d.PrevRunID = cr.PrevRunID
	if d.Changes, err = n.st.Changes(ctx, runID); err != nil {
		return nil, err
	}
	if d.Services, err = n.st.ExportServices(ctx, runID); err != nil {
		return nil, err
	}
	unstable, err := n.st.HostStates(ctx, model.HostUnstable)
	if err != nil {
		return nil, err
	}
	d.Unstable = map[netip.Addr]bool{}
	for _, h := range unstable {
		d.Unstable[h.IP.Unmap()] = true
	}
	var ips []netip.Addr
	seen := map[netip.Addr]bool{}
	for _, sv := range d.Services {
		if !seen[sv.Key.IP] {
			seen[sv.Key.IP] = true
			ips = append(ips, sv.Key.IP)
		}
	}
	if d.Notes, err = n.st.AnnotationsByIPs(ctx, ips); err != nil {
		return nil, err
	}
	rc, err := n.st.SafetyReceipt(ctx, runID)
	switch {
	case errors.Is(err, safety.ErrNoReceipt):
	case err != nil:
		return nil, err
	default:
		rep := safety.BuildReport(rc)
		d.Safety = &rep
	}
	return d, nil
}

// recoverDelivery turns a panic in an automatic delivery into a log line
// and a failed history row with a fixed message: the panic value may hold
// anything, the URL included.
func (n *Notifier) recoverDelivery(ctx context.Context, runID int64, event string) {
	if recover() == nil {
		return
	}
	n.log().Error("webhook notification panicked", "run", runID)
	defer func() {
		if recover() != nil {
			n.log().Error("webhook notification: recording the panic failed", "run", runID)
		}
	}()
	if err := n.record(ctx, store.NotifyDelivery{RunID: &runID, Trigger: TriggerAuto, Event: event,
		Error: panicMessage}); err != nil {
		n.log().Error("webhook notification: recording the panic failed", "run", runID, "err", err)
	}
}

// record writes the history row even when ctx has expired or was cancelled.
func (n *Notifier) record(ctx context.Context, row store.NotifyDelivery) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), recordTimeout)
	defer cancel()
	return n.st.RecordNotifyDelivery(ctx, row)
}

// Close stops the notifier: later OnRunDone calls are dropped and SendTest
// returns ErrClosed; deliveries in flight are cancelled (each still records
// its row). It waits for them until ctx is done.
func (n *Notifier) Close(ctx context.Context) error {
	n.mu.Lock()
	n.closed = true
	n.mu.Unlock()
	n.cancel()
	finished := make(chan struct{})
	go func() {
		n.wg.Wait()
		close(finished)
	}()
	select {
	case <-finished:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Wait blocks until deliveries in flight have finished.
func (n *Notifier) Wait() { n.wg.Wait() }

// begin registers a delivery in flight, unless the notifier is closed.
func (n *Notifier) begin() (func(), error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closed {
		return nil, ErrClosed
	}
	n.wg.Add(1)
	return n.wg.Done, nil
}

// withBase returns ctx additionally cancelled by Close.
func (n *Notifier) withBase(ctx context.Context) (context.Context, func()) {
	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(n.base, cancel)
	return ctx, func() { stop(); cancel() }
}

func (n *Notifier) timeout() time.Duration {
	if n.opt.Timeout > 0 {
		return n.opt.Timeout
	}
	return DefaultTimeout
}

func (n *Notifier) now() time.Time {
	if n.opt.Now != nil {
		return n.opt.Now()
	}
	return time.Now()
}

func (n *Notifier) userAgent() string {
	if n.opt.UserAgent != "" {
		return n.opt.UserAgent
	}
	return defaultUserAgent
}

func (n *Notifier) log() *slog.Logger {
	if n.opt.Log != nil {
		return n.opt.Log
	}
	return slog.Default()
}
