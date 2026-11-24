package runner

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/ctx42/testing/pkg/assert"
	"github.com/ctx42/testing/pkg/must"

	"github.com/chrobson/ramparteye/internal/model"
	"github.com/chrobson/ramparteye/internal/scan"
	"github.com/chrobson/ramparteye/internal/scope"
	"github.com/chrobson/ramparteye/internal/store"
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

func labScope() scope.Scope {
	return must.Value(scope.New([]netip.Prefix{netip.MustParsePrefix("10.20.0.0/18")}, nil, nil))
}

func pfx(s string) netip.Prefix { return netip.MustParsePrefix(s) }

type fixture struct {
	fs  *fakeStore
	sc  *fakeScanner
	fp  *fakeProber
	r   *Runner
	cfg store.ScanConfig
}

// setup returns a runner over a fake store holding one enabled manual scan
// profile (id 1, 4 workers, max rate 1000) with the given targets.
func setup(t *testing.T, targets ...model.Target) *fixture {
	t.Helper()
	fs := newFakeStore()
	cfg := store.ScanConfig{ID: 1, Name: "lab", TopPorts: 100, MaxRate: 1000, Workers: 4, Enabled: true}
	for i, tg := range targets {
		tg.ID = int64(i + 1)
		fs.targets[tg.ID] = tg
		cfg.TargetIDs = append(cfg.TargetIDs, tg.ID)
	}
	fs.configs = []store.ScanConfig{cfg}
	sc := newFakeScanner()
	fp := &fakeProber{}
	r := New(fs, sc, fp, nil, labScope(), Config{Log: quiet, RetryBackoff: time.Millisecond})
	return &fixture{fs: fs, sc: sc, fp: fp, r: r, cfg: cfg}
}

// runNow starts a manual run of the profile and waits until it stopped.
func (f *fixture) runNow(t *testing.T) int64 {
	t.Helper()
	id, err := f.r.Start(context.Background(), f.cfg.ID)
	assert.NoError(t, err)
	f.r.Wait()
	return id
}

func TestExecuteAllChunksOnce(t *testing.T) {
	f := setup(t,
		model.Target{Kind: model.TargetCIDR, Value: "10.20.0.0/21"}, // 8 chunks
		model.Target{Kind: model.TargetIP, Value: "10.20.9.9"},      // 1 chunk, down
	)
	runID := f.runNow(t)

	assert.Equal(t, store.RunDone, f.fs.runStatus(runID))
	chunks := f.fs.chunksOf(runID)
	assert.Len(t, 9, chunks)
	for _, c := range chunks {
		assert.Equal(t, store.ChunkDone, c.status)
		assert.Equal(t, 1, f.fs.leases[c.ID])
	}
	up, down := 0, 0
	for _, h := range f.fs.hosts {
		assert.Equal(t, runID, h.RunID)
		if h.Up {
			up++
		} else {
			down++
		}
	}
	assert.Equal(t, 8, up)
	assert.Equal(t, 1, down)
	assert.Len(t, 8, f.fs.services)
	for _, s := range f.fs.services {
		assert.Equal(t, runID, s.RunID)
	}
}

// The run's max rate R is split across its K workers.
func TestPerWorkerRateSplit(t *testing.T) {
	f := setup(t, model.Target{Kind: model.TargetCIDR, Value: "10.20.0.0/21"})
	f.runNow(t)
	assert.NotEmpty(t, f.sc.rates)
	for _, rate := range f.sc.rates {
		assert.Equal(t, 250, rate) // 1000 / 4
	}

	// More workers than chunks would idle with a share of the rate.
	f = setup(t, model.Target{Kind: model.TargetIP, Value: "10.20.0.5"})
	f.runNow(t)
	assert.Equal(t, []int{1000}, f.sc.rates)

	// The instance policy caps a profile's rate.
	f = setup(t, model.Target{Kind: model.TargetIP, Value: "10.20.0.5"})
	f.fs.configs[0].MaxRate = 0
	f.r.cfg.MaxRate = 600
	f.runNow(t)
	assert.Equal(t, []int{600}, f.sc.rates)
}

func TestPerWorkerRate(t *testing.T) {
	assert.Equal(t, 250, PerWorkerRate(1000, 4))
	assert.Equal(t, 1, PerWorkerRate(3, 8))
	assert.Equal(t, 0, PerWorkerRate(0, 4))
	assert.Equal(t, 100, PerWorkerRate(100, 0))
}

func TestRunStatus(t *testing.T) {
	cases := []struct {
		c    store.ChunkCounts
		want string
	}{
		{store.ChunkCounts{Done: 3}, store.RunDone},
		{store.ChunkCounts{Done: 2, Failed: 1}, store.RunDone},
		{store.ChunkCounts{Failed: 2}, store.RunFailed},
		{store.ChunkCounts{Done: 2, Pending: 1}, store.RunPaused},
		{store.ChunkCounts{Done: 2, Running: 1}, store.RunPaused},
		{store.ChunkCounts{}, store.RunDone},
	}
	for _, c := range cases {
		assert.Equal(t, c.want, RunStatus(c.c))
	}
}

func TestInterruptedChunkReturnsToPending(t *testing.T) {
	f := setup(t, model.Target{Kind: model.TargetCIDR, Value: "10.20.0.0/23"})
	f.cfg.Workers = 1
	blocked := pfx("10.20.1.0/24")
	f.sc.setBlock(blocked, true)

	runID := must.Value(f.r.createRun(context.Background(), f.cfg))
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond) // window end
	defer cancel()
	f.r.execute(newControl(ctx, time.Time{}), runID, f.cfg, time.Time{})
	assert.Equal(t, store.RunPaused, f.fs.runStatus(runID))
	var pending fakeChunk
	for _, c := range f.fs.chunksOf(runID) {
		if c.Prefix == blocked {
			pending = c
		} else {
			assert.Equal(t, store.ChunkDone, c.status)
		}
	}
	assert.Equal(t, store.ChunkPending, pending.status)
	assert.NotEmpty(t, pending.lastErr)

	// Next window: the chunk is picked up again and the run completes.
	f.sc.setBlock(blocked, false)
	f.r.execute(newControl(context.Background(), time.Time{}), runID, f.cfg, time.Time{})
	assert.Equal(t, store.RunDone, f.fs.runStatus(runID))
	got := f.fs.chunk(pending.ID)
	assert.Equal(t, 1, got.Attempts) // the interruption was refunded
	assert.Equal(t, 2, f.fs.leases[pending.ID])
	assert.True(t, f.fs.runs[runID].durationMs >= 100)
}

func TestFailingChunkRetriesThenFails(t *testing.T) {
	f := setup(t, model.Target{Kind: model.TargetCIDR, Value: "10.20.0.0/23"})
	bad := pfx("10.20.0.0/24")
	f.sc.fail[bad] = true
	runID := f.runNow(t)
	for _, c := range f.fs.chunksOf(runID) {
		if c.Prefix == bad {
			assert.Equal(t, store.ChunkFailed, c.status)
			assert.Equal(t, DefaultMaxAttempts, c.Attempts)
			assert.NotEmpty(t, c.lastErr)
		} else {
			assert.Equal(t, store.ChunkDone, c.status)
		}
	}
	assert.Equal(t, store.RunDone, f.fs.runStatus(runID)) // partial success counts as done

	// Every chunk failing fails the run.
	f.sc.fail[pfx("10.20.1.0/24")] = true
	runID = f.runNow(t)
	assert.Equal(t, store.RunFailed, f.fs.runStatus(runID))
}

// A failing chunk grouped with healthy ones does not take them down: the
// group is retried chunk by chunk within the same leases.
func TestFailingChunkDoesNotPoisonItsGroup(t *testing.T) {
	f := setup(t, model.Target{Kind: model.TargetCIDR, Value: "10.20.0.0/21"})
	f.fs.configs[0].Workers = 1
	bad := pfx("10.20.7.0/24")
	f.sc.fail[bad] = true
	runID := f.runNow(t)

	grouped := false
	for _, g := range f.sc.discoverGroups() {
		grouped = grouped || len(g) > 1
	}
	assert.True(t, grouped)
	for _, c := range f.fs.chunksOf(runID) {
		if c.Prefix == bad {
			assert.Equal(t, store.ChunkFailed, c.status)
			assert.Equal(t, DefaultMaxAttempts, c.Attempts)
			continue
		}
		assert.Equal(t, store.ChunkDone, c.status)
		assert.Equal(t, 1, c.Attempts)
	}
}

// Fast scans grow the nmap groups: after the first chunk is measured, the
// remaining chunks of a worker are scanned in one invocation.
func TestAdaptiveGroupSizing(t *testing.T) {
	f := setup(t, model.Target{Kind: model.TargetCIDR, Value: "10.20.0.0/21"})
	f.fs.configs[0].Workers = 1
	runID := f.runNow(t)

	groups := f.sc.discoverGroups()
	assert.Len(t, 2, groups)
	assert.Len(t, 1, groups[0]) // nothing measured yet: one /24
	assert.Len(t, 7, groups[1]) // fast network: the rest at once
	for _, c := range f.fs.chunksOf(runID) {
		assert.Equal(t, store.ChunkDone, c.status)
		assert.Equal(t, 1, c.hostsUp) // results attributed to their own chunk
	}
	assert.Len(t, 8, f.fs.services)
}

// Out-of-scope errors are final: retrying cannot help.
func TestOutOfScopeChunkFailsAtOnce(t *testing.T) {
	f := setup(t, model.Target{Kind: model.TargetCIDR, Value: "10.20.0.0/24"})
	f.r.sc = scopeRefusingScanner{}
	runID := f.runNow(t)
	chunks := f.fs.chunksOf(runID)
	assert.Len(t, 1, chunks)
	assert.Equal(t, store.ChunkFailed, chunks[0].status)
	assert.Equal(t, 1, chunks[0].Attempts)
	assert.Equal(t, store.RunFailed, f.fs.runStatus(runID))
}

func TestRecoverResetsRunning(t *testing.T) {
	f := setup(t, model.Target{Kind: model.TargetCIDR, Value: "10.20.0.0/23"})
	ctx := context.Background()
	runID := must.Value(f.r.createRun(ctx, f.cfg))
	assert.True(t, must.Value(f.fs.StartRun(ctx, runID)))
	c, _, _ := f.fs.LeaseChunk(ctx, runID) // the process "crashes" here
	assert.NoError(t, f.r.Recover(ctx))
	assert.Equal(t, store.ChunkPending, f.fs.chunk(c.ID).status)
	assert.Equal(t, store.RunPaused, f.fs.runStatus(runID))
}

// The auto port profile is decided per chunk: a single address keeps every
// port and the deep version pass when the run also covers a large range.
func TestAutoProfilePerChunk(t *testing.T) {
	f := setup(t,
		model.Target{Kind: model.TargetCIDR, Value: "10.20.0.0/24"},
		model.Target{Kind: model.TargetIP, Value: "10.20.9.9"},
		model.Target{Kind: model.TargetCIDR, Value: "10.20.10.0/28"},
	)
	f.r.cfg.AllPortsMaxAddrs = 16
	f.runNow(t)
	for _, c := range []string{"10.20.9.9/32", "10.20.10.0/28"} {
		o := f.sc.opts[pfx(c)]
		assert.Len(t, 65535, o.Ports)
		assert.True(t, o.DeepUnknown)
	}
	o := f.sc.opts[pfx("10.20.0.0/24")]
	assert.Nil(t, o.Ports)
	assert.False(t, o.DeepUnknown)
	for _, g := range f.sc.discoverGroups() {
		// small and large chunks are never mixed in one nmap invocation
		small := CountAddrs(g[:1]) <= 16
		for _, p := range g {
			assert.Equal(t, small, CountAddrs([]netip.Prefix{p}) <= 16)
		}
	}
}

func TestStartRefusedWithoutScope(t *testing.T) {
	f := setup(t, model.Target{Kind: model.TargetCIDR, Value: "10.20.0.0/24"})
	f.r.scope = scope.Scope{}
	_, err := f.r.Start(context.Background(), f.cfg.ID)
	assert.ErrorIs(t, scope.ErrNoScope, err)
	assert.Equal(t, 0, f.fs.runCount())
}

func TestStartWithoutTargetsInScope(t *testing.T) {
	f := setup(t, model.Target{Kind: model.TargetIP, Value: "192.0.2.1"})
	_, err := f.r.Start(context.Background(), f.cfg.ID)
	assert.ErrorIs(t, ErrNoTargets, err)
	assert.Equal(t, 0, f.fs.runCount())
}

func TestStartTwiceRefused(t *testing.T) {
	f := setup(t, model.Target{Kind: model.TargetCIDR, Value: "10.20.0.0/24"})
	f.sc.setBlock(pfx("10.20.0.0/24"), true)
	f.sc.started = make(chan netip.Prefix, 4)
	ctx := context.Background()
	runID := must.Value(f.r.Start(ctx, f.cfg.ID))
	<-f.sc.started
	_, err := f.r.Start(ctx, f.cfg.ID)
	assert.ErrorIs(t, ErrAlreadyRunning, err)
	assert.True(t, f.r.Stop(runID))
	f.r.Wait()
	assert.Equal(t, store.RunPaused, f.fs.runStatus(runID))
	assert.False(t, f.r.Stop(runID))
}

func TestOnRunDoneCalledOnce(t *testing.T) {
	f := setup(t, model.Target{Kind: model.TargetCIDR, Value: "10.20.0.0/23"})
	var mu sync.Mutex
	var calls []string
	f.r.OnRunDone = func(_ context.Context, id int64, status string) {
		mu.Lock()
		calls = append(calls, status)
		mu.Unlock()
	}
	blocked := pfx("10.20.1.0/24")
	f.sc.setBlock(blocked, true)
	f.sc.started = make(chan netip.Prefix, 16)

	// A paused session is not the end of the run.
	runID := must.Value(f.r.Start(context.Background(), f.cfg.ID))
	for p := range f.sc.started {
		if p == blocked {
			break
		}
	}
	f.r.Stop(runID)
	f.r.Wait()
	assert.Equal(t, store.RunPaused, f.fs.runStatus(runID))
	assert.Len(t, 0, calls)

	// The resumed session finishes it: exactly one call.
	f.sc.setBlock(blocked, false)
	f.sc.started = nil
	f.r.execute(newControl(context.Background(), time.Time{}), runID, f.cfg, time.Time{})
	assert.Equal(t, []string{store.RunDone}, calls)
	// Executing a finished run again never repeats the hook.
	f.r.execute(newControl(context.Background(), time.Time{}), runID, f.cfg, time.Time{})
	assert.Equal(t, []string{store.RunDone}, calls)

	// A failed run gets the hook with its status.
	calls = nil
	f.sc.fail[pfx("10.20.0.0/24")] = true
	f.sc.fail[blocked] = true
	f.runNow(t)
	assert.Equal(t, []string{store.RunFailed}, calls)
}

// A stale worker whose chunk was taken away keeps going; its result is
// dropped by the store.
func TestLeaseLostIsNotFatal(t *testing.T) {
	f := setup(t, model.Target{Kind: model.TargetCIDR, Value: "10.20.0.0/24"})
	f.fs.configs[0].Workers = 1
	stealing := &stealingStore{fakeStore: f.fs}
	f.r.st = stealing
	runID := f.runNow(t)
	// The completion was refused; the re-leased chunk stays with its new
	// owner, so the run is not finished by this process.
	assert.Equal(t, store.RunPaused, f.fs.runStatus(runID))
	assert.Len(t, 0, f.fs.hosts)
}

// stealingStore re-leases every chunk behind the worker's back right after
// handing it out, as a second process would after ResetRunning.
type stealingStore struct{ *fakeStore }

func (s *stealingStore) LeaseChunk(ctx context.Context, runID int64) (store.Chunk, bool, error) {
	c, ok, err := s.fakeStore.LeaseChunk(ctx, runID)
	if ok {
		s.mu.Lock()
		s.chunk(c.ID).Attempts++
		s.mu.Unlock()
	}
	return c, ok, err
}

// scopeRefusingScanner refuses every prefix like a scanner whose scope
// re-check right before exec failed.
type scopeRefusingScanner struct{}

func (scopeRefusingScanner) Discover(context.Context, []netip.Prefix, scan.Opts) (scan.Result, error) {
	return scan.Result{}, fmt.Errorf("%w: 10.20.0.0/24", scope.ErrOutOfScope)
}

func (scopeRefusingScanner) Services(context.Context, []netip.Addr, scan.Opts) (scan.Result, error) {
	return scan.Result{}, nil
}
