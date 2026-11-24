package runner

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"runtime/debug"
	"time"

	"github.com/chrobson/ramparteye/internal/model"
	"github.com/chrobson/ramparteye/internal/safety"
	"github.com/chrobson/ramparteye/internal/scan"
	"github.com/chrobson/ramparteye/internal/scope"
	"github.com/chrobson/ramparteye/internal/store"
	"github.com/chrobson/ramparteye/internal/target"
)

// interruptReason is recorded on a chunk cut by window end, stop or shutdown.
const interruptReason = "interrupted (window end or stop)"

// worker leases chunk groups and scans them until no chunk is left, ctx
// ends or the run is cancelled (checked before every lease, so a cancel
// request of another process is honoured at the next chunk boundary). Only
// store errors stop it; scan errors are recorded on the chunks. A panic
// fails the chunks the worker still holds and marks the session panicked.
func (r *Runner) worker(ctx context.Context, s *session) (err error) {
	var batch []store.Chunk
	defer func() {
		if p := recover(); p != nil {
			s.log.Error("scan worker panicked", "panic", p, "stack", string(debug.Stack()))
			s.panicked.Store(true)
			r.abandon(ctx, s, batch, fmt.Sprintf("internal error: %v", p))
			err = nil
		}
	}()
	for ctx.Err() == nil {
		if r.cancelRequested(ctx, s) {
			return nil
		}
		batch = nil
		lerr := r.leaseBatch(ctx, s, &batch)
		for _, g := range s.partition(batch) {
			if err := r.scanGroup(ctx, s, g); err != nil {
				return err
			}
		}
		if lerr != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("lease chunk: %w", lerr)
		}
		if len(batch) == 0 {
			return nil
		}
	}
	return nil
}

// abandon fails the chunks of a batch whose worker panicked. Chunks already
// settled are skipped: their lease is no longer current.
func (r *Runner) abandon(ctx context.Context, s *session, batch []store.Chunk, reason string) {
	dbctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), dbTimeout)
	defer cancel()
	for _, c := range batch {
		if err := r.st.FailChunk(dbctx, c, reason); err != nil && !errors.Is(err, store.ErrLeaseLost) {
			s.log.Error("chunk of a panicked worker not settled", "chunk", c.Prefix, "err", err)
		}
	}
}

// leaseBatch leases chunks until they cover the address count the sizer
// asks for (at least one chunk, at most maxGroupChunks).
// Each chunk is appended to *batch as soon as it is leased, so a panic
// midway still sees it.
func (r *Runner) leaseBatch(ctx context.Context, s *session, batch *[]store.Chunk) error {
	want := uint64(s.sizer.Next())
	var addrs uint64
	for len(*batch) < maxGroupChunks && (len(*batch) == 0 || addrs < want) {
		c, ok, err := r.st.LeaseChunk(ctx, s.runID)
		if err != nil {
			return err
		}
		if !ok {
			break
		}
		*batch = append(*batch, c)
		addrs += target.AddrCount(c.Prefix)
	}
	return nil
}

// partition splits a batch into groups scanned with the same options, so
// small and large chunks are never mixed in one nmap invocation. Order is
// kept.
func (s *session) partition(batch []store.Chunk) [][]store.Chunk {
	var small, large []store.Chunk
	for _, c := range batch {
		if s.isSmall(c.Prefix) {
			small = append(small, c)
		} else {
			large = append(large, c)
		}
	}
	var out [][]store.Chunk
	for _, g := range [][]store.Chunk{large, small} {
		if len(g) > 0 {
			out = append(out, g)
		}
	}
	return out
}

// scanGroup scans leased chunks in one nmap invocation per phase and
// settles every chunk: done with its own observations, interrupted (attempt
// refunded), retried or failed. A failing group of several chunks is
// rescanned chunk by chunk within the same leases, so one bad chunk cannot
// fail the others. Only store errors are returned.
func (r *Runner) scanGroup(ctx context.Context, s *session, chunks []store.Chunk) error {
	if ctx.Err() != nil {
		dbctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), dbTimeout)
		defer cancel()
		return r.settle(ctx, dbctx, s, chunks, ctx.Err(), true)
	}
	prefixes := make([]netip.Prefix, len(chunks))
	for i, c := range chunks {
		prefixes[i] = c.Prefix
	}
	t0 := r.cfg.Now()
	hosts, svcs, err := r.scan(ctx, s, prefixes, s.optsFor(prefixes[0]))
	dur := r.cfg.Now().Sub(t0)
	// The write timeout starts now: the scan itself may take far longer.
	dbctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), dbTimeout)
	defer cancel()
	if err != nil {
		interrupted := ctx.Err() != nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
		if !interrupted && len(chunks) > 1 {
			s.log.Warn("chunk group failed, scanning its chunks one by one", "chunks", len(chunks), "err", err)
			for _, c := range chunks {
				if err := r.scanGroup(ctx, s, []store.Chunk{c}); err != nil {
					return err
				}
			}
			return nil
		}
		return r.settle(ctx, dbctx, s, chunks, err, interrupted)
	}
	addrs := CountAddrs(prefixes)
	s.sizer.Observe(int(min(addrs, 1<<31)), dur)
	for _, c := range chunks {
		obs, cs := attribute(s, c, hosts, svcs)
		share := time.Duration(float64(dur) * float64(CountAddrs([]netip.Prefix{c.Prefix})) / float64(addrs))
		if err := r.st.CompleteChunk(dbctx, c, share, obs, cs); err != nil {
			if !errors.Is(err, store.ErrLeaseLost) {
				return fmt.Errorf("complete chunk %s: %w", c.Prefix, err)
			}
			s.log.Warn("chunk lease lost, result dropped", "chunk", c.Prefix)
		}
	}
	r.chunkSettled(dbctx, s)
	return nil
}

// attribute returns the observations of the group that belong to chunk c.
// An explicitly listed single address that did not answer is recorded as
// down; for larger chunks only live hosts are stored (absence = down).
func attribute(s *session, c store.Chunk, hosts []netip.Addr, svcs []model.ServiceObs) ([]model.HostObs, []model.ServiceObs) {
	var obs []model.HostObs
	for _, h := range hosts {
		if c.Prefix.Contains(h) {
			obs = append(obs, model.HostObs{RunID: c.RunID, IP: h, Hostname: firstName(s.hostnames[h]), Up: true})
		}
	}
	if c.Prefix.IsSingleIP() && len(obs) == 0 {
		a := c.Prefix.Addr()
		obs = append(obs, model.HostObs{RunID: c.RunID, IP: a, Hostname: firstName(s.hostnames[a])})
	}
	var out []model.ServiceObs
	for _, sv := range svcs {
		if c.Prefix.Contains(sv.Key.IP) {
			sv.RunID = c.RunID
			out = append(out, sv)
		}
	}
	return obs, out
}

func firstName(names []string) string {
	if len(names) == 0 {
		return ""
	}
	return names[0]
}

// settle records a scan error on each chunk: an interruption returns it to
// pending with its attempt refunded; a scope refusal or the last attempt
// fails it; anything else returns it to pending for a retry after a backoff.
func (r *Runner) settle(ctx, dbctx context.Context, s *session, chunks []store.Chunk, cause error, interrupted bool) error {
	for _, c := range chunks {
		var err error
		switch {
		case interrupted:
			err = r.st.InterruptChunk(dbctx, c, interruptReason)
		case c.Attempts >= r.cfg.MaxAttempts || errors.Is(cause, scope.ErrOutOfScope) || errors.Is(cause, scope.ErrNoScope):
			s.log.Warn("chunk failed", "chunk", c.Prefix, "attempt", c.Attempts, "err", cause)
			err = r.st.FailChunk(dbctx, c, cause.Error())
		default:
			s.log.Warn("chunk scan failed, will retry", "chunk", c.Prefix, "attempt", c.Attempts, "err", cause)
			r.backoff(ctx, c.Attempts)
			err = r.st.ReleaseChunk(dbctx, c, cause.Error())
		}
		if errors.Is(err, store.ErrLeaseLost) {
			s.log.Warn("chunk lease lost", "chunk", c.Prefix)
			continue
		}
		if err != nil {
			return fmt.Errorf("settle chunk %s: %w", c.Prefix, err)
		}
	}
	r.chunkSettled(dbctx, s)
	return nil
}

// backoff waits before a failed chunk is released for its next attempt:
// RetryBackoff doubled per attempt, capped at maxRetryBackoff. The worker
// keeps the lease meanwhile, so no other worker retries the chunk earlier.
// It returns early when ctx ends.
func (r *Runner) backoff(ctx context.Context, attempt int) {
	d := r.cfg.RetryBackoff << min(max(attempt-1, 0), 16)
	t := time.NewTimer(min(d, maxRetryBackoff))
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}

// chunkSettled persists the receipt delta and publishes progress after a
// group was settled.
func (r *Runner) chunkSettled(dbctx context.Context, s *session) {
	if err := r.saveSafety(dbctx, s); err != nil {
		s.log.Warn("safety receipt delta not saved, kept for the next save", "err", err)
	}
	counts, err := r.st.CountChunks(dbctx, s.runID)
	if err != nil {
		s.log.Warn("progress unknown", "err", err)
		return
	}
	r.publish(Event{RunID: s.runID, Kind: EventProgress, Progress: s.progress(counts), PPS: int(s.meter.Snapshot().PPS)})
}

// scan runs both nmap phases on prefixes. Every invocation is metered, also
// when it failed.
func (r *Runner) scan(ctx context.Context, s *session, prefixes []netip.Prefix, o scan.Opts) ([]netip.Addr, []model.ServiceObs, error) {
	res, err := r.sc.Discover(ctx, prefixes, o)
	meterRuns(s.meter, res.Runs)
	if err != nil {
		return nil, nil, fmt.Errorf("discovery: %w", err)
	}
	hosts := res.UpHosts()
	if len(hosts) == 0 {
		return nil, nil, nil
	}
	res, err = r.sc.Services(ctx, hosts, o)
	meterRuns(s.meter, res.Runs)
	if err != nil {
		return nil, nil, fmt.Errorf("services: %w", err)
	}
	return hosts, res.Services, nil
}

func meterRuns(m *safety.Meter, runs []scan.Run) {
	for _, run := range runs {
		m.AddNmap(safety.Invocation(run))
	}
}

// saveSafety adds the meter's delta since the last save to the stored
// receipt. On failure the delta goes back into the meter, so the next save
// carries it: nothing is dropped.
func (r *Runner) saveSafety(ctx context.Context, s *session) error {
	rc := s.meter.Drain(r.scope)
	rc.RunID, rc.PerWorkerRate = s.runID, s.perWorker
	rc.HTTPRateLimit, rc.HTTPBurst = r.cfg.HTTPRate, r.cfg.HTTPBurst
	if err := r.st.SaveSafetyReceipt(ctx, rc); err != nil {
		s.meter.Restore(rc)
		return err
	}
	return nil
}

// saveSafetyFinal saves the last delta of a session, retrying a few times;
// false when it could not be saved (the stored receipt is incomplete).
func (r *Runner) saveSafetyFinal(ctx context.Context, s *session) bool {
	var err error
	for attempt := range 3 {
		if err = r.saveSafety(ctx, s); err == nil {
			return true
		}
		select {
		case <-ctx.Done():
		case <-time.After(time.Duration(attempt+1) * 100 * time.Millisecond):
			continue
		}
		break
	}
	s.log.Error("safety receipt delta not saved", "err", err)
	return false
}
