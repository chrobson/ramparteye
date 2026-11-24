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
	"runtime/debug"
	"sync"
	"sync/atomic"
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
	StartRun(ctx context.Context, runID int64) error
	FinishRun(ctx context.Context, runID int64, status string, active time.Duration) error

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
)

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
	// (0 = unlimited).
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
	stale    map[int64]bool       // runs left running because FinishRun failed
	noFetch  sync.Once            // warns once that path probes are disabled
	wg       sync.WaitGroup

	events broker
}

type activeRun struct {
	configID int64
	manual   bool // started by Start: ignores the window
	cancel   context.CancelFunc
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
		a.cancel()
	}
	return ok
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

// session is one execution of a run: from start or resume until every chunk
// is finished or the context ends.
type session struct {
	runID     int64
	cfg       store.ScanConfig
	meter     *safety.Meter
	hostnames map[netip.Addr][]string
	small     scan.Opts // chunks of at most smallMax addresses
	large     scan.Opts
	smallMax  int
	sizer     *Sizer
	perWorker int
	total     int // chunks of the run
	log       *slog.Logger
	panicked  atomic.Bool // a worker panicked: the run fails
}

// optsFor returns the scan options of a chunk. The auto profile is decided
// per chunk, so a single address keeps every port and the deep version pass
// even when the run also covers a large range.
func (s *session) optsFor(p netip.Prefix) scan.Opts {
	if s.isSmall(p) {
		return s.small
	}
	return s.large
}

func (s *session) isSmall(p netip.Prefix) bool {
	return s.smallMax > 0 && CountAddrs([]netip.Prefix{p}) <= uint64(s.smallMax)
}

// newSession prepares a session; the error is a profile problem that makes
// the run unrunnable (port plan).
func (r *Runner) newSession(ctx context.Context, runID int64, cfg store.ScanConfig, scheduled time.Time) (*session, error) {
	s := &session{runID: runID, cfg: cfg, meter: safety.NewMeter(), smallMax: r.cfg.AllPortsMaxAddrs,
		sizer: NewSizer(0, r.cfg.GroupTarget), log: r.cfg.Log.With("run", runID, "profile", cfg.Name)}
	small, err := ResolvePorts(cfg, 1, r.cfg.AllPortsMaxAddrs, r.cfg.AllowedPorts, r.cfg.ExtraPorts)
	if err != nil {
		return nil, err
	}
	large, err := ResolvePorts(cfg, 1<<62, r.cfg.AllPortsMaxAddrs, r.cfg.AllowedPorts, r.cfg.ExtraPorts)
	if err != nil {
		return nil, err
	}
	// Hostnames for host observations and virtual host probes; a resolver
	// failure only loses names.
	if p, err := r.plan(ctx, cfg); err != nil {
		s.log.Warn("hostnames unavailable", "err", err)
	} else {
		s.hostnames = p.Hostnames
	}
	rate := cfg.MaxRate
	if r.cfg.MaxRate > 0 && (rate <= 0 || rate > r.cfg.MaxRate) {
		rate = r.cfg.MaxRate
	}
	s.meter.SetBudget(safety.Budget{RunPPS: rate, PolicyPPS: r.cfg.MaxRate, PathProbesPerHost: r.cfg.PathProbesPerHost})
	if !scheduled.IsZero() && cfg.HasWindow() {
		s.meter.SetWindow(safety.Window{Start: *cfg.WindowStart, End: *cfg.WindowEnd, Loc: scheduled.Location()})
	}
	// Probes spent by earlier sessions of the run count against the budget.
	if counts, err := r.st.SafetyProbes(ctx, runID); err != nil {
		s.log.Warn("path probe counts not loaded", "err", err)
	} else {
		s.meter.SeedProbes(counts)
	}
	base := scan.Opts{TopPorts: cfg.TopPorts, Privileged: r.cfg.Privileged}
	s.small, s.large = base, base
	s.small.Ports, s.small.ExtraPorts, s.small.DeepUnknown = small.Ports, small.Extra, s.smallMax > 0
	s.large.Ports, s.large.ExtraPorts = large.Ports, large.Extra
	s.small.MaxRate, s.large.MaxRate = rate, rate // split per worker in execute
	return s, nil
}

// execute runs the pending chunks of a run until none is left or ctx ends.
// The run is then done (post-processed), failed (every chunk failed) or
// paused (chunks left). scheduled is the scheduler time of a windowed run;
// zero for a manual run.
func (r *Runner) execute(ctx context.Context, runID int64, cfg store.ScanConfig, scheduled time.Time) {
	started := r.cfg.Now()
	var s *session
	settled := false
	settle := func(status, msg string) {
		settled = true
		r.finish(ctx, s, runID, status, r.cfg.Now().Sub(started), msg)
	}
	// A panic anywhere in the run (store, pipeline, a worker) fails the run
	// instead of the process; the run still gets its finished event and
	// OnRunDone.
	defer func() {
		p := recover()
		if p == nil {
			return
		}
		r.cfg.Log.Error("scan run panicked", "run", runID, "panic", p, "stack", string(debug.Stack()))
		if !settled {
			settle(store.RunFailed, fmt.Sprintf("%s; internal error: %v", store.RunFailed, p))
		}
	}()

	s, err := r.newSession(ctx, runID, cfg, scheduled)
	if err != nil {
		r.cfg.Log.Error("scan run cannot start", "run", runID, "profile", cfg.Name, "err", err)
		s = nil
		settle(store.RunFailed, store.RunFailed+"; "+err.Error())
		return
	}
	ctx = safety.WithMeter(ctx, s.meter)
	// When the outcome cannot be read, the run is saved as paused (best
	// effort) so the scheduler resumes it; it is never left running.
	if err := r.st.StartRun(ctx, runID); err != nil {
		s.log.Error("scan run not started", "err", err)
		settle(store.RunPaused, store.RunPaused+"; start: "+err.Error())
		return
	}
	counts, err := r.st.CountChunks(ctx, runID)
	if err != nil {
		s.log.Error("scan run not started", "err", err)
		settle(store.RunPaused, store.RunPaused+"; count chunks: "+err.Error())
		return
	}
	s.total = counts.Pending + counts.Running + counts.Done + counts.Failed
	// More workers than chunks would only idle while taking a share of the
	// rate, so a single-address run gets the whole rate; more workers than
	// packets/s would exceed the rate at 1 packet/s each.
	k := max(cfg.Workers, 1)
	if n := counts.Pending; n > 0 && n < k {
		k = n
	}
	if rate := s.small.MaxRate; rate > 0 && k > rate {
		k = rate
	}
	s.perWorker = PerWorkerRate(s.small.MaxRate, k)
	s.small.MaxRate, s.large.MaxRate = s.perWorker, s.perWorker
	s.log.Info("scan run started", "workers", k, "rate_per_worker", s.perWorker, "chunks", s.total,
		"pending", counts.Pending)
	r.publish(Event{RunID: runID, Kind: EventStarted, Progress: s.progress(counts)})

	var wg sync.WaitGroup
	for range k {
		wg.Go(func() {
			defer func() {
				if p := recover(); p != nil {
					s.log.Error("scan worker panicked", "panic", p, "stack", string(debug.Stack()))
					s.panicked.Store(true)
				}
			}()
			if err := r.worker(ctx, s); err != nil {
				s.log.Error("scan worker stopped", "err", err)
			}
		})
	}
	wg.Wait()
	if s.panicked.Load() {
		settle(store.RunFailed, store.RunFailed+"; internal error in a scan worker")
		return
	}

	// Persist the outcome even when ctx is already done.
	dbctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), dbTimeout)
	defer cancel()
	if counts, err = r.st.CountChunks(dbctx, runID); err != nil {
		s.log.Error("scan run outcome unknown", "err", err)
		settle(store.RunPaused, store.RunPaused+"; count chunks: "+err.Error())
		return
	}
	status := RunStatus(counts)
	msg := status
	if status == store.RunDone {
		// Post-processing is not bound to the window deadline; every probe
		// has its own deadline.
		if err := r.postProcess(context.WithoutCancel(ctx), s); err != nil {
			s.log.Error("post-processing failed", "err", err)
			msg = status + "; post-processing: " + err.Error()
		}
	}
	settle(status, msg)
}

// finish saves the session's last receipt delta (s may be nil), stores the
// run status, publishes the finished event and calls OnRunDone for a final
// status. The finished event is always published. When the status cannot be
// stored, the run stays running in the database: it is remembered as stale
// so Tick resumes it instead of taking it for a run of another process, and
// OnRunDone waits for the status to be stored.
//
// A crash between FinishRun and OnRunDone loses the hook call for that run
// (the run is final and never resumed); persisting "hook delivered" is left
// to the hook's consumers (Tasks 15/18).
func (r *Runner) finish(ctx context.Context, s *session, runID int64, status string, active time.Duration, msg string) {
	dbctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), dbTimeout)
	defer cancel()
	log := r.cfg.Log.With("run", runID)
	e := Event{RunID: runID, Kind: EventFinished}
	if s != nil {
		e.PPS = int(s.meter.Snapshot().PPS)
		if !r.saveSafetyFinal(dbctx, s) {
			msg += "; safety receipt incomplete"
		} else if rc, err := r.st.SafetyReceipt(dbctx, runID); err == nil {
			rep := safety.BuildReport(rc)
			msg += "; safety " + string(rep.Status)
			log.Info("safety receipt", "status", rep.Status, "nmap_packets", rc.NmapPackets,
				"effective_pps", rep.EffectivePPS, "http_get", rc.HTTPGet, "http_head", rc.HTTPHead,
				"http_other", rc.HTTPOther, "targets_outside_scope", rc.TargetsOutsideAllowlist)
		}
	}
	if err := r.st.FinishRun(dbctx, runID, status, active); err != nil {
		log.Error("scan run status not saved, will resume", "status", status, "err", err)
		r.setStale(runID, true)
		e.Message = msg + "; status not saved: " + err.Error()
		r.publish(e)
		return
	}
	r.setStale(runID, false)
	log.Info("scan run stopped", "status", status, "active_ms", active.Milliseconds())
	final := status == store.RunDone || status == store.RunFailed || status == store.RunCancelled
	e.Message = msg
	if final {
		e.Progress = 1
	}
	r.publish(e)
	if final {
		r.runEnded(context.WithoutCancel(ctx), runID, status)
	}
}

// setStale records whether a run's last status could not be stored.
func (r *Runner) setStale(runID int64, stale bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !stale {
		delete(r.stale, runID)
		return
	}
	if r.stale == nil {
		r.stale = map[int64]bool{}
	}
	r.stale[runID] = true
}

func (r *Runner) isStale(runID int64) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.stale[runID]
}

// runEnded calls OnRunDone once per run.
func (r *Runner) runEnded(ctx context.Context, runID int64, status string) {
	r.mu.Lock()
	if r.ended == nil {
		r.ended = map[int64]bool{}
	}
	seen := r.ended[runID]
	r.ended[runID] = true
	r.mu.Unlock()
	if !seen && r.OnRunDone != nil {
		r.OnRunDone(ctx, runID, status)
	}
}

func (s *session) progress(c store.ChunkCounts) float64 {
	if s.total == 0 {
		return 0
	}
	return scanShare * float64(c.Done+c.Failed) / float64(s.total)
}

// RunStatus derives the run status from chunk counts after workers stopped.
func RunStatus(c store.ChunkCounts) string {
	switch {
	case c.Pending > 0 || c.Running > 0:
		return store.RunPaused
	case c.Done == 0 && c.Failed > 0:
		return store.RunFailed
	default:
		return store.RunDone
	}
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
func (r *Runner) register(runID, configID int64, manual bool, cancel context.CancelFunc) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.active == nil {
		r.active = map[int64]*activeRun{}
	}
	if _, ok := r.active[runID]; ok {
		return false
	}
	r.active[runID] = &activeRun{configID: configID, manual: manual, cancel: cancel}
	return true
}

func (r *Runner) unregister(runID int64) {
	r.mu.Lock()
	delete(r.active, runID)
	r.mu.Unlock()
}

// reserve marks a profile as getting a new run; false when it already has
// an active or starting run.
func (r *Runner) reserve(configID int64) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.starting[configID] || r.activeLocked(configID) != nil {
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
	var ctx context.Context
	var cancel context.CancelFunc
	if deadline.IsZero() {
		ctx, cancel = context.WithCancel(base)
	} else {
		ctx, cancel = context.WithDeadline(base, deadline)
	}
	if !r.register(runID, cfg.ID, manual, cancel) {
		cancel()
		return
	}
	r.wg.Go(func() {
		defer r.unregister(runID)
		defer cancel()
		r.execute(ctx, runID, cfg, scheduled)
	})
}
