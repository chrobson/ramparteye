package dojo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/chrobson/ramparteye/internal/config"
	"github.com/chrobson/ramparteye/internal/model"
	"github.com/chrobson/ramparteye/internal/secret"
	"github.com/chrobson/ramparteye/internal/sig"
	"github.com/chrobson/ramparteye/internal/store"
)

// Push triggers recorded in the push history.
const (
	TriggerAuto   = "auto"
	TriggerManual = "manual"
	TriggerCLI    = "cli"
)

const (
	// DefaultPushTimeout bounds one automatic push after a run.
	DefaultPushTimeout = 2 * time.Minute
	// recordTimeout bounds writing the history row, which happens even when
	// the push itself ran out of time or was cancelled.
	recordTimeout = 10 * time.Second
	// testTitlePrefix names the DefectDojo test of a scan profile.
	testTitlePrefix = "RampartEye – "
	adHocProfile    = "ad-hoc"
	// SkippedStale is the error text of a push that was skipped because a newer run of the same profile had already been pushed.
	SkippedStale = "skipped: newer run already pushed"
	panicMessage = "internal error: DefectDojo push panicked"
)

var (
	// ErrNotConfigured is returned by PushRun when no DefectDojo URL or API
	// token is configured. Nothing is pushed and nothing is recorded.
	ErrNotConfigured = errors.New("DefectDojo is not configured")
	// ErrClosed is returned by PushRun after Close. Nothing is recorded.
	ErrClosed = errors.New("DefectDojo pusher is closed")
	// ErrStaleRun refuses a manual push of a run older than the newest run
	// of the same profile already pushed: its reimport would close findings
	// that the newer run still sees.
	ErrStaleRun = errors.New("a newer run of this scan profile has already been pushed")
)

// HistoryStore reads the push history.
type HistoryStore interface {
	LatestDojoPush(ctx context.Context, okOnly bool) (*store.DojoPush, error)
}

// PushStore is the persistence the pusher needs; *store.Store satisfies it.
type PushStore interface {
	HistoryStore
	sig.Lister
	DojoRun(ctx context.Context, runID int64) (store.DojoRun, error)
	DojoLastPush(ctx context.Context, runID int64) (store.DojoLastPush, error)
	RecordDojoPush(ctx context.Context, p store.DojoPush) error
}

var _ PushStore = (*store.Store)(nil)

// PushRecord is the outcome of one push attempt.
type PushRecord struct {
	RunID    int64
	At       time.Time
	Findings int
	Added    int
	Closed   int
	OK       bool
	Error    string
	Trigger  string
	// Skipped is a push not sent because a newer run of the
	// same profile had already been pushed (OK is false, Error SkippedStale).
	Skipped bool
}

// ChipState is what the top bar DefectDojo chip shows.
type ChipState struct {
	Configured bool
	// LastOK is the outcome of the latest push attempt, skipped ones
	// ignored (nil = never pushed).
	LastOK *bool
	// LastAt is the time of that attempt (zero = never pushed).
	LastAt time.Time
	// Findings is the finding count of the latest successful push.
	Findings int
}

// Pusher sends the findings of finished runs to DefectDojo and records
// every attempt in the push history.
//
// Shutdown order: stop the runner first (no more OnRunDone calls), then
// call Close, which cancels pushes in flight (each still records its row)
// and waits for them.
type Pusher struct {
	st       PushStore
	settings func(context.Context) (Settings, error)
	client   func(Settings) *Client

	// Timeout bounds one automatic push (DefaultPushTimeout when zero).
	Timeout time.Duration
	// Log receives automatic push failures (slog.Default when nil).
	Log *slog.Logger

	base   context.Context // cancelled by Close
	cancel context.CancelFunc

	mu     sync.Mutex
	closed bool
	locks  map[string]*sync.Mutex // per DefectDojo test title
	wg     sync.WaitGroup
}

// NewPusher returns a pusher. settings must return the effective settings
// with Token filled (see StoredSettings); client builds the API client for
// them (see DefaultClient).
func NewPusher(st PushStore, settings func(ctx context.Context) (Settings, error), client func(Settings) *Client) *Pusher {
	base, cancel := context.WithCancel(context.Background())
	return &Pusher{st: st, settings: settings, client: client, base: base, cancel: cancel,
		locks: map[string]*sync.Mutex{}}
}

// DefaultClient returns a verified-TLS client for s.
func DefaultClient(s Settings) *Client { return NewClient(s.URL, s.Token, nil) }

// StoredSettings returns a settings source for NewPusher: LoadSettings with
// the API token opened when one is configured. A token that cannot be
// opened is reported with ErrTokenUnavailable.
func StoredSettings(st SettingsStore, box *secret.Box, cfg config.Config) func(context.Context) (Settings, error) {
	return func(ctx context.Context) (Settings, error) {
		s, err := LoadSettings(ctx, st, box, cfg)
		if err != nil || !s.TokenSet {
			return s, err
		}
		if s.Token, err = loadToken(ctx, st, box, cfg); err != nil {
			return Settings{}, err
		}
		return s, nil
	}
}

// OnRunDone is the runner hook. A run that ended "done" is pushed in the
// background when auto-push is on and DefectDojo is configured; any other
// status is ignored, as is every call after Close. It never blocks the
// runner, never panics into it and never reports an error to it: failures
// land in the push history. Settings that cannot be loaded at all (store
// unreachable) are only logged, since whether auto-push is on is unknown;
// a configured token that cannot be opened is recorded as a failed push.
func (p *Pusher) OnRunDone(ctx context.Context, runID int64, status string) {
	if status != store.RunDone {
		return
	}
	done, err := p.begin()
	if err != nil {
		p.log().Warn("DefectDojo auto-push dropped: pusher closed", "run", runID)
		return
	}
	go func() {
		defer done()
		timeout := p.Timeout
		if timeout <= 0 {
			timeout = DefaultPushTimeout
		}
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), timeout)
		defer cancel()
		ctx, stop := p.withBase(ctx)
		defer stop()
		defer p.recoverPush(ctx, runID)

		s, err := p.settings(ctx)
		switch {
		case err != nil && !errors.Is(err, ErrTokenUnavailable):
			p.log().Warn("DefectDojo auto-push: settings unavailable", "run", runID, "err", err)
			return
		case err == nil && (!s.AutoPush || !s.configured()):
			return
		}
		if _, err := p.push(ctx, s, err, runID, TriggerAuto); err != nil {
			p.log().Warn("DefectDojo auto-push failed", "run", runID, "err", err)
		}
	}()
}

// recoverPush turns a panic in an automatic push into a log line and a
// failed history row. The row carries a fixed message: the panic value may
// hold anything, the token included.
func (p *Pusher) recoverPush(ctx context.Context, runID int64) {
	v := recover()
	if v == nil {
		return
	}
	p.log().Error("DefectDojo auto-push panicked", "run", runID)
	defer func() {
		if recover() != nil {
			p.log().Error("DefectDojo auto-push: recording the panic failed", "run", runID)
		}
	}()
	if err := p.record(ctx, store.DojoPush{RunID: runIDPtr(runID), Trigger: TriggerAuto,
		Endpoint: "reimport-scan", Error: panicMessage}); err != nil {
		p.log().Error("DefectDojo auto-push: recording the panic failed", "run", runID, "err", err)
	}
}

// Close stops the pusher: later OnRunDone calls are dropped and PushRun
// returns ErrClosed; pushes in flight are cancelled (each still records its
// failed row). It waits for them until ctx is done.
func (p *Pusher) Close(ctx context.Context) error {
	p.mu.Lock()
	p.closed = true
	p.mu.Unlock()
	p.cancel()
	finished := make(chan struct{})
	go func() {
		p.wg.Wait()
		close(finished)
	}()
	select {
	case <-finished:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Wait blocks until pushes in flight have finished.
func (p *Pusher) Wait() { p.wg.Wait() }

// begin registers a push in flight, unless the pusher is closed.
func (p *Pusher) begin() (func(), error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil, ErrClosed
	}
	p.wg.Add(1)
	return p.wg.Done, nil
}

// withBase returns ctx additionally cancelled by Close.
func (p *Pusher) withBase(ctx context.Context) (context.Context, func()) {
	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(p.base, cancel)
	return ctx, func() { stop(); cancel() }
}

// PushRun reimports the full service inventory of run runID (0 = latest
// finished run) into the DefectDojo test of its scan profile. Every attempt
// is recorded, failed or not, except when DefectDojo is not configured
// (ErrNotConfigured), the pusher is closed (ErrClosed) or the trigger is
// unknown. A run older than the newest pushed run of its profile is recorded as skipped (not
// failed); an automatic push returns no error, any other trigger gets
// ErrStaleRun. A failed push returns the record together with the
// error.
func (p *Pusher) PushRun(ctx context.Context, runID int64, trigger string) (PushRecord, error) {
	done, err := p.begin()
	if err != nil {
		return PushRecord{}, err
	}
	defer done()
	ctx, stop := p.withBase(ctx)
	defer stop()
	s, err := p.settings(ctx)
	return p.push(ctx, s, err, runID, trigger)
}

// Status reports the chip state with the current settings.
func (p *Pusher) Status(ctx context.Context) (ChipState, error) {
	s, err := p.settings(ctx)
	if err != nil {
		return ChipState{}, err
	}
	return Status(ctx, p.st, s)
}

func (p *Pusher) push(ctx context.Context, s Settings, settingsErr error, runID int64, trigger string) (PushRecord, error) {
	switch trigger {
	case TriggerAuto, TriggerManual, TriggerCLI:
	default:
		return PushRecord{}, fmt.Errorf("unknown push trigger %q", trigger)
	}
	if settingsErr == nil && !s.configured() {
		return PushRecord{}, ErrNotConfigured
	}
	rec := PushRecord{RunID: runID, Trigger: trigger}
	row := store.DojoPush{RunID: runIDPtr(runID), Trigger: trigger, Endpoint: "reimport-scan"}
	if settingsErr != nil {
		return p.fail(ctx, rec, row, s.Token, settingsErr)
	}
	snap, err := p.st.DojoRun(ctx, runID)
	if err != nil {
		return p.fail(ctx, rec, row, s.Token, fmt.Errorf("load run for DefectDojo: %w", err))
	}
	rec.RunID = snap.Run.ID
	row.RunID = runIDPtr(snap.Run.ID)

	title := TestTitle(snap.ProfileName)
	lock := p.lock(title)
	lock.Lock()
	defer lock.Unlock()

	// Read under the lock: a push of the same profile may just have ended.
	last, err := p.st.DojoLastPush(ctx, snap.Run.ID)
	if err != nil {
		return p.fail(ctx, rec, row, s.Token, fmt.Errorf("load DefectDojo push history: %w", err))
	}
	// Only profile runs replace their test (close_old_findings), so only
	// they can undo a newer push.
	if snap.ProfileName != "" && last.RunID != nil && snap.Run.ID < *last.RunID {
		// Recorded as skipped, not failed: the chip must not turn red
		// because the operator pushed an old run.
		rec.Skipped, rec.Error, rec.At = true, SkippedStale, time.Now()
		row.Skipped, row.Error = true, SkippedStale
		recErr := p.record(ctx, row)
		if trigger == TriggerAuto {
			return rec, recErr
		}
		return rec, errors.Join(fmt.Errorf("run %d: %w (run %d)", snap.Run.ID, ErrStaleRun, *last.RunID), recErr)
	}

	svcs, anns := pushInput(ctx, p.st, snap)
	findings := BuildFindings(snap.Run.Date(), svcs, anns)
	rec.Findings, row.Findings = len(findings), len(findings)
	body, err := NewCodec().Marshal(findings)
	if err != nil {
		return p.fail(ctx, rec, row, s.Token, err)
	}
	res, err := p.client(s).Reimport(ctx, PushParams{
		ProductType: s.ProductType,
		Product:     s.Product,
		Engagement:  s.Engagement,
		TestTitle:   title,
		// Runs without a profile (ad-hoc scans, imports) cover arbitrary
		// target sets that share one test: they never close findings.
		CloseOldFindings: s.CloseMissing && snap.ProfileName != "",
	}, body)
	if err != nil {
		return p.fail(ctx, rec, row, s.Token, err)
	}
	rec.Added, rec.Closed = deltas(res.Statistics, len(findings), last.Findings)
	rec.OK = true
	row.Added, row.Closed, row.OK, row.Statistics = rec.Added, rec.Closed, true, res.Statistics
	if id := int64(res.ID()); id != 0 {
		row.TestID = &id
	}
	rec.At = time.Now()
	return rec, p.record(ctx, row)
}

// fail records a failed attempt with the token masked and returns err
// (masked too) joined with any error writing the history row.
func (p *Pusher) fail(ctx context.Context, rec PushRecord, row store.DojoPush, token string, err error) (PushRecord, error) {
	msg := err.Error()
	if token != "" && strings.Contains(msg, token) {
		msg = strings.ReplaceAll(msg, token, "[redacted]")
		err = errors.New(msg)
	}
	rec.At, rec.Error = time.Now(), msg
	row.Error = msg
	return rec, errors.Join(err, p.record(ctx, row))
}

// record writes the history row even when ctx has expired or was cancelled.
func (p *Pusher) record(ctx context.Context, row store.DojoPush) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), recordTimeout)
	defer cancel()
	if err := p.st.RecordDojoPush(ctx, row); err != nil {
		return fmt.Errorf("record DefectDojo push: %w", err)
	}
	return nil
}

func (p *Pusher) lock(title string) *sync.Mutex {
	p.mu.Lock()
	defer p.mu.Unlock()
	l, ok := p.locks[title]
	if !ok {
		l = &sync.Mutex{}
		p.locks[title] = l
	}
	return l
}

func (p *Pusher) log() *slog.Logger {
	if p.Log != nil {
		return p.Log
	}
	return slog.Default()
}

func runIDPtr(id int64) *int64 {
	if id == 0 {
		return nil
	}
	return &id
}

func (s Settings) configured() bool { return s.URL != "" && s.Token != "" }

// TestTitle names the DefectDojo test of a scan profile: one test per
// profile, so reimports of a profile replace its previous findings.
func TestTitle(profile string) string {
	if profile == "" {
		profile = adHocProfile
	}
	return testTitlePrefix + profile
}

// Status reports the chip state: configured when s has a URL and a token,
// the outcome of the latest push attempt (skipped ones ignored) and the
// finding count of the latest successful push.
func Status(ctx context.Context, st HistoryStore, s Settings) (ChipState, error) {
	chip := ChipState{Configured: s.URL != "" && (s.TokenSet || s.Token != "")}
	last, err := st.LatestDojoPush(ctx, false)
	if err != nil {
		return chip, fmt.Errorf("load DefectDojo push history: %w", err)
	}
	if last == nil {
		return chip, nil
	}
	ok := last.OK
	chip.LastOK, chip.LastAt = &ok, last.At
	if !ok {
		if last, err = st.LatestDojoPush(ctx, true); err != nil {
			return chip, fmt.Errorf("load DefectDojo push history: %w", err)
		}
	}
	if last != nil {
		chip.Findings = last.Findings
	}
	return chip, nil
}

// pushInput converts a run snapshot to BuildFindings input, with signature
// metadata attached to the detections.
func pushInput(ctx context.Context, st sig.Lister, snap store.DojoRun) ([]Service, []Annotation) {
	metas := sig.Metas(ctx, st)
	svcs := make([]Service, len(snap.Services))
	for i, sv := range snap.Services {
		svcs[i] = Service{ServiceObs: sv.ServiceObs, Hostname: sv.Hostname,
			Detections: append([]model.Detection(nil), sv.Detections...)}
		if sv.HTTP != nil {
			svcs[i].HTTP = &HTTPSummary{URL: sv.HTTP.URL, Status: sv.HTTP.Status, Title: sv.HTTP.Title}
		}
		model.AttachMeta(svcs[i].Detections, metas)
	}
	anns := make([]Annotation, len(snap.Annotations))
	for i, a := range snap.Annotations {
		anns[i] = Annotation{Key: a.Key, Comment: a.Comment, Tags: a.Tags, Severity: a.Severity,
			FalsePositive: a.FalsePositive}
	}
	return svcs, anns
}

// deltas returns the findings added and closed by a reimport. DefectDojo
// reports them in statistics.delta (created + reactivated, closed). When the
// response carries no delta they are the net change of the finding count
// against the previous successful push of the same profile (everything is
// added on its first push).
func deltas(stats json.RawMessage, findings int, prev *int) (added, closed int) {
	type total struct {
		Total struct {
			Total int `json:"total"`
		} `json:"total"`
	}
	var s struct {
		Delta *struct {
			Created     total `json:"created"`
			Reactivated total `json:"reactivated"`
			Closed      total `json:"closed"`
		} `json:"delta"`
	}
	if len(stats) > 0 && json.Unmarshal(stats, &s) == nil && s.Delta != nil {
		d := s.Delta
		return d.Created.Total.Total + d.Reactivated.Total.Total, d.Closed.Total.Total
	}
	if prev == nil {
		return findings, 0
	}
	return max(findings-*prev, 0), max(*prev-findings, 0)
}
