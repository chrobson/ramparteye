// Package runner executes scan runs. A run's targets are resolved against
// the scope and split into chunks stored with the run; K worker goroutines
// lease chunks (FOR UPDATE SKIP LOCKED in the store), scan them in groups
// sized from measured scan time with a per-worker rate R/K, and store the
// observations. A run stops at the end of its scan window (paused, resumed
// in the next window), retries a failing chunk up to 3 times and, once every
// chunk is finished, fingerprints HTTP services, matches signatures and
// applies the diff (pipeline.go). Every nmap invocation and HTTP request is
// metered into the run's safety receipt.
package runner

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/chrobson/ramparteye/internal/diff"
	"github.com/chrobson/ramparteye/internal/httpfp"
	"github.com/chrobson/ramparteye/internal/model"
	"github.com/chrobson/ramparteye/internal/safety"
	"github.com/chrobson/ramparteye/internal/scan"
	"github.com/chrobson/ramparteye/internal/scope"
	"github.com/chrobson/ramparteye/internal/sig"
	"github.com/chrobson/ramparteye/internal/store"
	"github.com/chrobson/ramparteye/internal/target"
)

// Store is the persistence the runner needs; *store.Store implements it.
type Store interface {
	ResetRunning(ctx context.Context) (int64, error)
	ScanConfigs(ctx context.Context) ([]store.ScanConfig, error)
	ScanConfig(ctx context.Context, id int64) (store.ScanConfig, error)
	ScanTargets(ctx context.Context, ids []int64) ([]model.Target, error)
	CreateRun(ctx context.Context, configID *int64, chunks []netip.Prefix) (int64, error)
	LastRun(ctx context.Context, configID int64) (*store.RunInfo, error)
	OpenRuns(ctx context.Context) ([]store.RunInfo, error)
	StartRun(ctx context.Context, runID int64) (bool, error)
	FinishRun(ctx context.Context, runID int64, status string, active time.Duration) (bool, error)
	CancelOpenRuns(ctx context.Context, by *int64) (requested, finished []int64, err error)
	CancelRequested(ctx context.Context, runID int64) (bool, error)
	InsertAudit(ctx context.Context, userID *int64, action, entity string, details any) error

	LeaseChunk(ctx context.Context, runID int64) (store.Chunk, bool, error)
	CompleteChunk(ctx context.Context, c store.Chunk, dur time.Duration, hosts []model.HostObs, svcs []model.ServiceObs) error
	ReleaseChunk(ctx context.Context, c store.Chunk, reason string) error
	InterruptChunk(ctx context.Context, c store.Chunk, reason string) error
	FailChunk(ctx context.Context, c store.Chunk, reason string) error
	CountChunks(ctx context.Context, runID int64) (store.ChunkCounts, error)

	RunServices(ctx context.Context, runID int64) ([]model.ServiceObs, error)
	RunHostObs(ctx context.Context, runID int64) ([]model.HostObs, error)
	SaveHTTPObs(ctx context.Context, o model.HTTPObs) error
	SaveLegacyTLS(ctx context.Context, serviceID int64, r store.LegacyTLS) error
	ReplaceDetections(ctx context.Context, serviceID int64, ds []model.Detection) error
	ApplyRun(ctx context.Context, runID int64, cfg diff.Config, now time.Time) (store.ApplyResult, error)

	SaveSafetyReceipt(ctx context.Context, r safety.Receipt) error
	SafetyReceipt(ctx context.Context, runID int64) (safety.Receipt, error)
	SafetyProbes(ctx context.Context, runID int64) (map[netip.Addr]int, error)

	Signatures(ctx context.Context) ([]store.SignatureRow, error)
	SyncBuiltinSignatures(ctx context.Context, rows []store.SignatureRow) ([]string, error)
}

var _ Store = (*store.Store)(nil)

// DefaultMaxAttempts is how many times a chunk is tried before it fails.
const DefaultMaxAttempts = 3

// maxGroupChunks bounds how many chunks one worker scans in one group.
const maxGroupChunks = 64

// maxRetryBackoff caps the wait before a failed chunk is retried.
const maxRetryBackoff = 30 * time.Second

// dbTimeout bounds the writes that must survive a cancelled run context
// (window end, stop, shutdown).
const dbTimeout = 15 * time.Second

var (
	// ErrAlreadyRunning is returned by Start for a profile with an active run.
	ErrAlreadyRunning = errors.New("a run of this scan profile is already active")
	// ErrNoTargets is returned when no target of a profile is inside the scope.
	ErrNoTargets = errors.New("scan profile has no targets inside the scan scope")
	// ErrRunCancelled is the cause of a cancelled run's context.
	ErrRunCancelled = errors.New("scan run cancelled")
)

// AuditCancelAll is the audit action of CancelAll.
const AuditCancelAll = "scans.cancel_all"

// Config holds the instance-wide settings of a Runner. Zero values select
// the defaults.
type Config struct {
	Privileged bool // -sS instead of -sT
	// MaxRate caps every profile's packets/s (all workers of a run);
	// 0 = no cap.
	MaxRate int
	// AllowedPorts (RAMPART_SCAN_PORTS) restricts phase 2 to these ports.
	AllowedPorts []int
	// ExtraPorts is the built-in extra pass of the top profile
	// (nil = scan.DefaultExtraPorts).
	ExtraPorts []int
	// AllPortsMaxAddrs: chunks of at most this many addresses get every port
	// and the deep version pass under the auto profile (0 = never).
	AllPortsMaxAddrs int
	ChunkBits        int // IPv4 chunk prefix length, default 24
	MaxAttempts      int // default 3
	// RetryBackoff is the wait before a failed chunk's second attempt,
	// doubled per further attempt and capped at 30 s (default 1 s).
	RetryBackoff time.Duration
	// GroupTarget is the desired duration of one nmap group (default 90 s).
	GroupTarget time.Duration
	Resolver    target.Resolver // domain targets; nil = system resolver
	Unstable    diff.Config

	// HTTPTimeout is the per-request timeout used for the overall probe
	// deadline (3x) when the prober does not report its own.
	HTTPTimeout time.Duration
	HTTPRate    float64 // prober request rate, recorded in the receipt
	HTTPBurst   int
	// PathProbesPerHost is the per-host path probe budget of a run
	// (0 = unlimited, safety.PathProbesDisabled = no path probes).
	PathProbesPerHost int
	ProbeWorkers      int // parallel HTTP probes, default 8

	Log *slog.Logger
	Now func() time.Time
}

func (c Config) withDefaults() Config {
	if c.ChunkBits <= 0 || c.ChunkBits > 32 {
		c.ChunkBits = DefaultChunkBits4
	}
	if c.MaxAttempts <= 0 {
		c.MaxAttempts = DefaultMaxAttempts
	}
	if c.RetryBackoff <= 0 {
		c.RetryBackoff = time.Second
	}
	if c.ExtraPorts == nil {
		c.ExtraPorts = scan.DefaultExtraPorts
	}
	if c.HTTPTimeout <= 0 {
		c.HTTPTimeout = httpfp.DefaultTimeout
	}
	if c.HTTPRate <= 0 {
		c.HTTPRate = httpfp.DefaultRate
	}
	if c.HTTPBurst <= 0 {
		c.HTTPBurst = httpfp.DefaultBurst
	}
	if c.ProbeWorkers <= 0 {
		c.ProbeWorkers = 8
	}
	if c.Log == nil {
		c.Log = slog.Default()
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	return c
}

// Runner executes and schedules scan runs.
type Runner struct {
	// OnRunDone, if set, is called exactly once per run when it reaches a
	// final status (done, failed or cancelled), after the run's results,
	// diff and safety receipt are stored. It is not called for a paused
	// session. Set it before the first Start or Tick.
	OnRunDone func(ctx context.Context, runID int64, status string)

	st    Store
	sc    scan.Scanner
	fp    httpfp.Prober
	eng   *sig.Engine
	scope scope.Scope
	cfg   Config

	mu       sync.Mutex
	active   map[int64]*activeRun // by run id
	starting map[int64]bool       // profile ids with a run being created
	ended    map[int64]bool       // runs whose OnRunDone was called
	stale    map[int64]staleRun   // runs left running because FinishRun failed
	noFetch  sync.Once            // warns once that path probes are disabled
	sigMu    sync.Mutex           // serialises LoadSignatures
	wg       sync.WaitGroup

	events broker
}

type activeRun struct {
	configID int64
	manual   bool // started by Start: ignores the window
	ctl      *control
}

// New returns a Runner. sc re-checks the scope right before every nmap exec;
// fp fingerprints HTTP services (nil = none) and should carry the same
// scope; eng holds the signatures (nil = no detections) and is never
// modified by a run: each run matches with its own copy whose path probes go
// through the run's budget. s is the scan scope: an empty scope refuses every
// run.
func New(st Store, sc scan.Scanner, fp httpfp.Prober, eng *sig.Engine, s scope.Scope, cfg Config) *Runner {
	return &Runner{st: st, sc: sc, fp: fp, eng: eng, scope: s, cfg: cfg.withDefaults()}
}

// Start creates a run of the profile and executes it in the background,
// ignoring the profile's window (manual "scan now"). The run is bound to
// ctx, which must live as long as the process: cancelling it pauses the run.
// Use Wait to block until it stopped.
func (r *Runner) Start(ctx context.Context, configID int64) (int64, error) {
	cfg, err := r.st.ScanConfig(ctx, configID)
	if err != nil {
		return 0, err
	}
	if !r.reserve(cfg.ID) {
		return 0, fmt.Errorf("%w: %s", ErrAlreadyRunning, cfg.Name)
	}
	defer r.release(cfg.ID)
	runID, err := r.createRun(ctx, cfg)
	if err != nil {
		return 0, err
	}
	r.launch(ctx, runID, cfg, time.Time{}, time.Time{}, true)
	return runID, nil
}

// Stop cancels a run executing in this process; it becomes paused.
func (r *Runner) Stop(runID int64) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	a, ok := r.active[runID]
	if ok {
		a.ctl.stop()
	}
	return ok
}

// CancelAll requests the cancel of every unfinished scan run, here and in
// other processes, on behalf of user by (0 = system). Runs executing in
// this process are cancelled at once: their nmap processes are killed,
// interrupted chunks return to pending, the safety receipt is saved and the
// run ends cancelled; post-processing stops and the diff is not applied. A
// cancel request is stored for every unfinished run, so another process
// stops its runs at its next chunk boundary and no cancelled run is ever
// resumed; queued and paused runs are marked cancelled at once. OnRunDone
// gets "cancelled".
//
// It is a point-in-time sweep: runs created after its transaction are not
// covered. It returns the ids of the runs a cancel was requested for,
// ascending (a run that finished meanwhile keeps its own final status), and
// records the audit entry AuditCancelAll, also when storing the requests
// failed.
func (r *Runner) CancelAll(ctx context.Context, by int64) ([]int64, error) {
	var actor *int64
	if by > 0 {
		actor = &by
	}
	// The store writes outlive a cancelled caller.
	dbctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), dbTimeout)
	defer cancel()
	ids := r.cancelActive(nil)
	requested, finished, err := r.st.CancelOpenRuns(dbctx, actor)
	// A run launched here between the first sweep and the transaction is
	// running in the store: cancel it at once too.
	if err == nil {
		ids = append(ids, r.cancelActive(requested)...)
	}
	ids = append(ids, requested...)
	slices.Sort(ids)
	ids = slices.Compact(ids)
	details := map[string]any{"requested": ids}
	if err != nil {
		err = fmt.Errorf("store cancel requests: %w", err)
		details["error"] = err.Error()
	}
	for _, id := range finished {
		r.publish(Event{RunID: id, Kind: EventFinished, Progress: 1, Message: store.RunCancelled})
		r.runEnded(context.WithoutCancel(ctx), id, store.RunCancelled)
	}
	r.cfg.Log.Info("scan runs cancel requested", "runs", ids, "by", by, "err", err)
	if aerr := r.st.InsertAudit(dbctx, actor, AuditCancelAll, "scan_runs", details); aerr != nil {
		err = errors.Join(err, fmt.Errorf("audit: %w", aerr))
	}
	return ids, err
}

// cancelActive cancels the runs executing in this process (all of them
// when only is nil, else those listed) and returns their ids.
func (r *Runner) cancelActive(only []int64) []int64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	var ids []int64
	for id, a := range r.active {
		if only != nil && !slices.Contains(only, id) {
			continue
		}
		a.ctl.cancel(ErrRunCancelled)
		ids = append(ids, id)
	}
	return ids
}

// Wait blocks until every run started by Start or Tick has stopped.
func (r *Runner) Wait() { r.wg.Wait() }

// ActiveRuns returns the ids of the runs executing in this process.
func (r *Runner) ActiveRuns() []int64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]int64, 0, len(r.active))
	for id := range r.active {
		out = append(out, id)
	}
	return out
}

// createRun expands the profile's targets into chunks and stores a queued run.
func (r *Runner) createRun(ctx context.Context, cfg store.ScanConfig) (int64, error) {
	if r.scope.Empty() {
		return 0, scope.ErrNoScope
	}
	plan, err := r.plan(ctx, cfg)
	if err != nil {
		return 0, err
	}
	if len(plan.Chunks) == 0 {
		return 0, fmt.Errorf("%w: %s", ErrNoTargets, cfg.Name)
	}
	id := cfg.ID
	return r.st.CreateRun(ctx, &id, plan.Chunks)
}

func (r *Runner) plan(ctx context.Context, cfg store.ScanConfig) (Plan, error) {
	targets, err := r.st.ScanTargets(ctx, cfg.TargetIDs)
	if err != nil {
		return Plan{}, fmt.Errorf("load targets: %w", err)
	}
	p := BuildPlan(ctx, targets, r.scope, r.cfg.Resolver, r.cfg.ChunkBits)
	for _, s := range p.Skipped {
		r.cfg.Log.Warn("target not scanned", "profile", cfg.Name, "reason", s)
	}
	return p, nil
}

// PerWorkerRate splits a run's max rate r across k workers (at least 1
// packet/s each). 0 means unlimited.
func PerWorkerRate(r, k int) int {
	if r <= 0 {
		return 0
	}
	return max(r/max(k, 1), 1)
}

// register marks a run active in this process; false if it already is.
func (r *Runner) register(runID int64, a *activeRun) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.active == nil {
		r.active = map[int64]*activeRun{}
	}
	if _, ok := r.active[runID]; ok {
		return false
	}
	r.active[runID] = a
	return true
}

func (r *Runner) unregister(runID int64) {
	r.mu.Lock()
	delete(r.active, runID)
	r.mu.Unlock()
}

// reserve marks a profile as getting a new run; false when it already has
// an active, starting or stale run.
func (r *Runner) reserve(configID int64) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.starting[configID] || r.activeLocked(configID) != nil || r.staleLocked(configID) {
		return false
	}
	if r.starting == nil {
		r.starting = map[int64]bool{}
	}
	r.starting[configID] = true
	return true
}

func (r *Runner) release(configID int64) {
	r.mu.Lock()
	delete(r.starting, configID)
	r.mu.Unlock()
}

func (r *Runner) activeLocked(configID int64) *activeRun {
	for _, a := range r.active {
		if a.configID == configID {
			return a
		}
	}
	return nil
}

func (r *Runner) isActive(runID int64) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, ok := r.active[runID]
	return ok
}

// launch executes a run in a goroutine. A non-zero deadline (window end)
// pauses the run when reached; manual runs are not paused by the scheduler.
func (r *Runner) launch(base context.Context, runID int64, cfg store.ScanConfig, deadline, scheduled time.Time, manual bool) {
	c := newControl(base, deadline)
	if !r.register(runID, &activeRun{configID: cfg.ID, manual: manual, ctl: c}) {
		c.release()
		return
	}
	r.wg.Go(func() {
		defer r.unregister(runID)
		defer c.release()
		r.execute(c, runID, cfg, scheduled)
	})
}
