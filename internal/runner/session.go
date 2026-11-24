package runner

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"

	"github.com/chrobson/ramparteye/internal/safety"
	"github.com/chrobson/ramparteye/internal/scan"
	"github.com/chrobson/ramparteye/internal/store"
)

// control holds the contexts of one run session. ctx ends at the window
// deadline, on Stop, on shutdown (base) and when the run is cancelled;
// abort ends only when the run is cancelled (CancelAll, or a cancel request
// of another process), so post-processing, which outlives the window and a
// shutdown, still stops for a cancel.
type control struct {
	ctx    context.Context
	abort  context.Context
	stop   context.CancelFunc      // ends ctx: the run pauses
	cancel context.CancelCauseFunc // ends abort and ctx: the run is cancelled
	unlink func() bool
}

func newControl(base context.Context, deadline time.Time) *control {
	c := &control{}
	c.abort, c.cancel = context.WithCancelCause(context.WithoutCancel(base))
	if deadline.IsZero() {
		c.ctx, c.stop = context.WithCancel(base)
	} else {
		c.ctx, c.stop = context.WithDeadline(base, deadline)
	}
	c.unlink = context.AfterFunc(c.abort, c.stop)
	return c
}

// release frees the contexts once the session ended.
func (c *control) release() {
	c.unlink()
	c.stop()
	c.cancel(nil)
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
	ctl       *control
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
func (r *Runner) newSession(ctx context.Context, c *control, runID int64, cfg store.ScanConfig, scheduled time.Time) (*session, error) {
	s := &session{runID: runID, cfg: cfg, ctl: c, meter: safety.NewMeter(), smallMax: r.cfg.AllPortsMaxAddrs,
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
// The run is then done (post-processed), failed (every chunk failed),
// cancelled or paused (chunks left). scheduled is the scheduler time of a
// windowed run; zero for a manual run.
func (r *Runner) execute(c *control, runID int64, cfg store.ScanConfig, scheduled time.Time) {
	ctx := c.ctx
	started := r.cfg.Now()
	var s *session
	settled := false
	settle := func(status, msg string) {
		settled = true
		r.finish(ctx, s, runID, cfg.ID, status, r.cfg.Now().Sub(started), msg)
	}
	// A panic anywhere in the run (store, pipeline) fails the run instead of
	// the process; the run still gets its finished event and OnRunDone.
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

	s, err := r.newSession(ctx, c, runID, cfg, scheduled)
	if err != nil {
		r.cfg.Log.Error("scan run cannot start", "run", runID, "profile", cfg.Name, "err", err)
		s = nil
		settle(store.RunFailed, store.RunFailed+"; "+err.Error())
		return
	}
	ctx = safety.WithMeter(ctx, s.meter)
	// When the outcome cannot be read, the run is saved as paused (best
	// effort) so the scheduler resumes it; it is never left running.
	ok, err := r.st.StartRun(ctx, runID)
	if err != nil {
		s.log.Error("scan run not started", "err", err)
		settle(store.RunPaused, store.RunPaused+"; start: "+err.Error())
		return
	}
	if !ok { // finished meanwhile, e.g. cancelled while it was launched
		s.log.Info("scan run already finished, not started")
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
	switch {
	case r.cancelRequested(dbctx, s):
		status, msg = store.RunCancelled, store.RunCancelled
	case status == store.RunDone:
		// Post-processing is not bound to the window deadline (every probe
		// has its own deadline) but stops when the run is cancelled; the
		// diff of a cancelled run is never applied.
		applied, err := r.postProcess(safety.WithMeter(c.abort, s.meter), s)
		switch {
		case !applied && c.abort.Err() != nil:
			status, msg = store.RunCancelled, store.RunCancelled
		case err != nil:
			s.log.Error("post-processing failed", "err", err)
			msg = status + "; post-processing: " + err.Error()
		}
	}
	settle(status, msg)
}

// cancelRequested reports whether the run is cancelled: by CancelAll in
// this process, or by a cancel request stored by another process, which
// then cancels the session here too.
func (r *Runner) cancelRequested(ctx context.Context, s *session) bool {
	if s.ctl.abort.Err() != nil {
		return true
	}
	ok, err := r.st.CancelRequested(ctx, s.runID)
	if err != nil {
		if ctx.Err() == nil {
			s.log.Warn("cancel request not checked", "err", err)
		}
		return false
	}
	if ok {
		s.log.Info("scan run cancel requested")
		s.ctl.cancel(ErrRunCancelled)
	}
	return ok
}

// finish saves the session's last receipt delta (s may be nil), stores the
// run status, publishes the finished event and calls OnRunDone for a final
// status. The finished event is always published. When the status cannot be
// stored (an error or a panic before it was stored), the run stays running
// in the database: it is remembered as stale with its status, Tick stores
// that status later without executing the run again, and OnRunDone waits
// for the status to be stored.
//
// A crash between FinishRun and OnRunDone loses the hook call for that run
// (the run is final and never resumed); persisting "hook delivered" is left
// to the hook's consumers (Task 18).
func (r *Runner) finish(ctx context.Context, s *session, runID, configID int64, status string, active time.Duration, msg string) {
	dbctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), dbTimeout)
	defer cancel()
	log := r.cfg.Log.With("run", runID)
	e := Event{RunID: runID, Kind: EventFinished}
	stored := false
	defer func() {
		p := recover()
		if p == nil {
			return
		}
		log.Error("finishing scan run panicked", "status", status, "panic", p, "stack", string(debug.Stack()))
		if !stored {
			r.setStale(runID, staleRun{configID: configID, status: status, active: active})
			e.Message = fmt.Sprintf("%s; status not saved: internal error: %v", msg, p)
			r.publish(e)
		}
	}()
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
	applied, err := r.st.FinishRun(dbctx, runID, status, active)
	if err != nil {
		log.Error("scan run status not saved, will retry", "status", status, "err", err)
		r.setStale(runID, staleRun{configID: configID, status: status, active: active})
		e.Message = msg + "; status not saved: " + err.Error()
		r.publish(e)
		return
	}
	stored = true
	r.statusStored(ctx, e, status, applied, active, msg)
}

// statusStored ends a session whose FinishRun succeeded: the run is no
// longer stale, the finished event e is published and OnRunDone is called
// for a final status. applied is false when the run already had a final
// status (set by CancelAll or another process), which is kept: whoever set
// it reported it.
func (r *Runner) statusStored(ctx context.Context, e Event, status string, applied bool, active time.Duration, msg string) {
	r.clearStale(e.RunID)
	log := r.cfg.Log.With("run", e.RunID)
	if !applied {
		log.Info("scan run already finished, status kept", "status", status)
		e.Message = msg + "; run already finished"
		r.publish(e)
		return
	}
	log.Info("scan run stopped", "status", status, "active_ms", active.Milliseconds())
	final := finalStatus(status)
	e.Message = msg
	if final {
		e.Progress = 1
	}
	r.publish(e)
	if final {
		r.runEnded(context.WithoutCancel(ctx), e.RunID, status)
	}
}

func finalStatus(s string) bool {
	return s == store.RunDone || s == store.RunFailed || s == store.RunCancelled
}

// staleRun is a run whose last status could not be stored: it stays
// running in the database until Tick stores status.
type staleRun struct {
	configID int64
	status   string
	active   time.Duration // scanning time of the session, added once
}

func (r *Runner) setStale(runID int64, sr staleRun) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.stale == nil {
		r.stale = map[int64]staleRun{}
	}
	r.stale[runID] = sr
}

func (r *Runner) clearStale(runID int64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.stale, runID)
}

func (r *Runner) isStale(runID int64) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, ok := r.stale[runID]
	return ok
}

// staleLocked reports whether a profile has a stale run; r.mu is held.
func (r *Runner) staleLocked(configID int64) bool {
	for _, sr := range r.stale {
		if sr.configID == configID {
			return true
		}
	}
	return false
}

// retryStale stores the status of every stale run without executing it
// again. A paused run with a cancel request is stored cancelled.
func (r *Runner) retryStale(ctx context.Context) {
	r.mu.Lock()
	stale := make(map[int64]staleRun, len(r.stale))
	for id, sr := range r.stale {
		stale[id] = sr
	}
	r.mu.Unlock()
	for id, sr := range stale {
		log := r.cfg.Log.With("run", id)
		status := sr.status
		if !finalStatus(status) {
			if ok, err := r.st.CancelRequested(ctx, id); err != nil {
				log.Warn("cancel request not checked", "err", err)
			} else if ok {
				status = store.RunCancelled
			}
		}
		applied, err := r.st.FinishRun(ctx, id, status, sr.active)
		if err != nil {
			log.Error("scan run status still not saved", "status", status, "err", err)
			continue
		}
		r.statusStored(ctx, Event{RunID: id, Kind: EventFinished}, status, applied, sr.active, status)
	}
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
