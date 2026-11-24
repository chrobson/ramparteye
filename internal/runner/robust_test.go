package runner

import (
	"context"
	"regexp"
	"sync"
	"testing"
	"time"

	"github.com/ctx42/testing/pkg/assert"
	"github.com/ctx42/testing/pkg/must"

	"github.com/chrobson/ramparteye/internal/model"
	"github.com/chrobson/ramparteye/internal/store"
)

// hookRecorder records OnRunDone calls.
type hookRecorder struct {
	mu    sync.Mutex
	calls []string
}

func (h *hookRecorder) hook(_ context.Context, _ int64, status string) {
	h.mu.Lock()
	h.calls = append(h.calls, status)
	h.mu.Unlock()
}

func (h *hookRecorder) got() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.calls...)
}

// startCollect subscribes, starts a manual run and returns its events once
// the run stopped.
func startCollect(t *testing.T, f *fixture) (int64, []Event) {
	t.Helper()
	ch, unsubscribe := f.r.Subscribe()
	defer unsubscribe()
	runID := must.Value(f.r.Start(context.Background(), f.cfg.ID))
	events := collect(t, ch, runID)
	f.r.Wait()
	return runID, events
}

// A CountChunks failure at session start saves the run paused (never left
// running) and publishes the finished event; the next tick resumes it.
func TestCountChunksErrorAtStartPausesRun(t *testing.T) {
	f := setup(t, model.Target{Kind: model.TargetCIDR, Value: "10.20.0.0/24"})
	h := &hookRecorder{}
	f.r.OnRunDone = h.hook
	f.fs.countFail = map[int]bool{1: true}
	runID, events := startCollect(t, f)
	assert.Equal(t, store.RunPaused, f.fs.runStatus(runID))
	assert.Contain(t, "count chunks", events[len(events)-1].Message)
	assert.Len(t, 0, h.got())

	f.r.Tick(context.Background(), time.Now())
	f.r.Wait()
	assert.Equal(t, store.RunDone, f.fs.runStatus(runID))
	assert.Equal(t, []string{store.RunDone}, h.got())
}

// The same for the final CountChunks after the workers stopped.
func TestCountChunksErrorAtEndPausesRun(t *testing.T) {
	f := setup(t, model.Target{Kind: model.TargetCIDR, Value: "10.20.0.0/24"})
	f.fs.configs[0].Workers = 1
	f.fs.countFail = map[int]bool{3: true} // start, after the chunk, final
	runID, events := startCollect(t, f)
	assert.Equal(t, store.RunPaused, f.fs.runStatus(runID))
	assert.Equal(t, EventFinished, events[len(events)-1].Kind)

	f.r.Tick(context.Background(), time.Now())
	f.r.Wait()
	assert.Equal(t, store.RunDone, f.fs.runStatus(runID))
}

// When FinishRun fails the run stays running in the database. The finished
// event is still published, OnRunDone waits, and the next tick retries the
// stored status without executing the run again (no second scan or
// fingerprinting) instead of taking it for a run of another process.
func TestFinishRunErrorRetriedByTick(t *testing.T) {
	f, _ := pipelineFixture(t, headerSig)
	h := &hookRecorder{}
	f.r.OnRunDone = h.hook
	f.fs.finishFails = 1
	runID, events := startCollect(t, f)
	assert.Equal(t, store.RunRunning, f.fs.runStatus(runID))
	last := events[len(events)-1]
	assert.Equal(t, EventFinished, last.Kind)
	assert.Contain(t, "status not saved", last.Message)
	assert.Len(t, 0, h.got())
	assert.True(t, f.r.isStale(runID))
	discovers, probes := f.sc.discoverCount(), len(f.fp.endpoints())

	f.r.Tick(context.Background(), time.Now())
	f.r.Wait()
	assert.Equal(t, store.RunDone, f.fs.runStatus(runID))
	assert.Equal(t, []string{store.RunDone}, h.got())
	assert.Equal(t, 1, f.fs.runCount())
	assert.False(t, f.r.isStale(runID))
	assert.Equal(t, discovers, f.sc.discoverCount())
	assert.Equal(t, probes, len(f.fp.endpoints()))
	assert.Equal(t, []int64{runID}, f.fs.appliedRuns())
}

// A stale run of a disabled (or out-of-window) profile is still retried.
func TestStaleRunOfDisabledProfileRetried(t *testing.T) {
	f := setup(t, model.Target{Kind: model.TargetCIDR, Value: "10.20.0.0/24"})
	h := &hookRecorder{}
	f.r.OnRunDone = h.hook
	f.fs.finishFails = 1
	runID := f.runNow(t)
	f.fs.configs[0].Enabled = false

	f.r.Tick(context.Background(), time.Now())
	f.r.Wait()
	assert.Equal(t, store.RunDone, f.fs.runStatus(runID))
	assert.Equal(t, []string{store.RunDone}, h.got())
}

// A stale run occupies its profile: no second run is started by Start or
// by the scheduler while its status is not stored.
func TestStaleRunOccupiesProfile(t *testing.T) {
	f := setup(t, model.Target{Kind: model.TargetCIDR, Value: "10.20.0.0/24"})
	f.fs.configs[0].EveryMinutes = ptr(1)
	f.fs.finishFails = 1
	runID := f.runNow(t)

	_, err := f.r.Start(context.Background(), f.cfg.ID)
	assert.ErrorIs(t, ErrAlreadyRunning, err)
	f.fs.finishFails = 1 // the retry fails too
	f.r.Tick(context.Background(), time.Now().Add(time.Hour))
	f.r.Wait()
	assert.Equal(t, 1, f.fs.runCount())
	assert.True(t, f.r.isStale(runID))
}

// A panic while finishing, before the status is stored, leaves the run
// stale (not running and invisible): the next tick stores its status.
func TestFinishPanicMarksStale(t *testing.T) {
	f := setup(t, model.Target{Kind: model.TargetCIDR, Value: "10.20.0.0/24"})
	h := &hookRecorder{}
	f.r.OnRunDone = h.hook
	f.fs.rcptPanic = true
	runID, events := startCollect(t, f)
	assert.Equal(t, store.RunRunning, f.fs.runStatus(runID))
	assert.True(t, f.r.isStale(runID))
	assert.Equal(t, EventFinished, events[len(events)-1].Kind)
	assert.Len(t, 0, h.got())

	f.fs.mu.Lock()
	f.fs.rcptPanic = false
	f.fs.mu.Unlock()
	f.r.Tick(context.Background(), time.Now())
	f.r.Wait()
	assert.Equal(t, store.RunDone, f.fs.runStatus(runID))
	assert.Equal(t, []string{store.RunDone}, h.got())
	assert.Equal(t, 1, f.sc.discoverCount())
}

// A stale paused run with a cancel request is stored cancelled.
func TestStalePausedRunCancelled(t *testing.T) {
	f := setup(t, model.Target{Kind: model.TargetCIDR, Value: "10.20.0.0/24"})
	h := &hookRecorder{}
	f.r.OnRunDone = h.hook
	runID := startBlocked(t, f)
	f.fs.mu.Lock()
	f.fs.finishFails = 1
	f.fs.mu.Unlock()
	f.r.Stop(runID)
	f.r.Wait()
	assert.True(t, f.r.isStale(runID))
	f.fs.requestCancel(runID)

	f.r.Tick(context.Background(), time.Now())
	f.r.Wait()
	assert.Equal(t, store.RunCancelled, f.fs.runStatus(runID))
	assert.Equal(t, []string{store.RunCancelled}, h.got())
}

// A panicking scanner fails the run instead of the process: the run is
// settled failed, publishes its finished event and calls OnRunDone once.
func TestScannerPanicFailsRun(t *testing.T) {
	f := setup(t, model.Target{Kind: model.TargetCIDR, Value: "10.20.0.0/23"})
	h := &hookRecorder{}
	f.r.OnRunDone = h.hook
	f.sc.panics = true
	runID, events := startCollect(t, f)
	assert.Equal(t, store.RunFailed, f.fs.runStatus(runID))
	last := events[len(events)-1]
	assert.Equal(t, 1.0, last.Progress)
	assert.Contain(t, "internal error", last.Message)
	assert.Equal(t, []string{store.RunFailed}, h.got())
	// The chunks the panicking workers held are settled, not left running.
	for _, c := range f.fs.chunksOf(runID) {
		assert.Equal(t, store.ChunkFailed, c.status)
	}
}

// A panicking prober costs only its service: the run is done, its other
// steps (diff) still ran.
func TestProberPanicIsServiceError(t *testing.T) {
	f, _ := pipelineFixture(t, headerSig)
	h := &hookRecorder{}
	f.r.OnRunDone = h.hook
	f.fp.panics = true
	runID, events := startCollect(t, f)
	assert.Equal(t, store.RunDone, f.fs.runStatus(runID))
	assert.Contain(t, "internal error", events[len(events)-1].Message)
	assert.Equal(t, []int64{runID}, f.fs.applied)
	assert.Equal(t, []string{store.RunDone}, h.got())
}

// A panic in the run goroutine itself (here the diff) settles the run failed.
func TestRunPanicFailsRun(t *testing.T) {
	f := setup(t, model.Target{Kind: model.TargetCIDR, Value: "10.20.0.0/24"})
	h := &hookRecorder{}
	f.r.OnRunDone = h.hook
	f.fs.applyPanic = true
	runID, events := startCollect(t, f)
	assert.Equal(t, store.RunFailed, f.fs.runStatus(runID))
	assert.Contain(t, "apply exploded", events[len(events)-1].Message)
	assert.Equal(t, []string{store.RunFailed}, h.got())
}

// The finished message carries the safety report status of the stored
// receipt, or says the receipt is incomplete when its last delta could not
// be saved (no status is claimed then).
func TestFinishedMessageSafetyStatus(t *testing.T) {
	f := setup(t, model.Target{Kind: model.TargetCIDR, Value: "10.20.0.0/24"})
	_, events := startCollect(t, f)
	assert.Regexp(t, regexp.MustCompile(`^done; safety (ok|incomplete|failed)$`), events[len(events)-1].Message)

	f = setup(t, model.Target{Kind: model.TargetCIDR, Value: "10.20.0.0/24"})
	f.fs.configs[0].Workers = 1
	f.fs.failSaves = 100
	_, events = startCollect(t, f)
	msg := events[len(events)-1].Message
	assert.Contain(t, "safety receipt incomplete", msg)
	assert.NotContain(t, "safety ok", msg)
}

// Workers are capped at the run's rate, so the total stays within it even
// at the 1 packet/s per-worker minimum.
func TestWorkersCappedAtRate(t *testing.T) {
	f := setup(t, model.Target{Kind: model.TargetCIDR, Value: "10.20.0.0/22"}) // 4 chunks
	f.fs.configs[0].MaxRate = 2
	f.sc.delay = 30 * time.Millisecond
	f.runNow(t)
	for _, rate := range f.sc.rates {
		assert.Equal(t, 1, rate)
	}
	assert.True(t, f.sc.maxFlight <= 2)
}

// A failed chunk waits before its next attempt: RetryBackoff doubled per
// attempt.
func TestRetryBackoff(t *testing.T) {
	f := setup(t, model.Target{Kind: model.TargetCIDR, Value: "10.20.0.0/24"})
	f.r.cfg.RetryBackoff = 40 * time.Millisecond
	f.sc.fail[pfx("10.20.0.0/24")] = true
	start := time.Now()
	runID := f.runNow(t)
	assert.Equal(t, store.RunFailed, f.fs.runStatus(runID))
	assert.True(t, time.Since(start) >= 120*time.Millisecond) // 40 ms + 80 ms before attempts 2 and 3
}

func TestRetryBackoffCapped(t *testing.T) {
	f := setup(t)
	f.r.cfg.RetryBackoff = time.Hour
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	start := time.Now()
	f.r.backoff(ctx, 10)
	assert.True(t, time.Since(start) < time.Second) // returns when ctx ends
}

// A panic while leasing a batch fails the chunks already leased for it.
func TestLeasePanicSettlesLeasedChunks(t *testing.T) {
	f := setup(t, model.Target{Kind: model.TargetCIDR, Value: "10.20.0.0/24"})
	f.fs.configs[0].Workers = 1
	f.r.cfg.ChunkBits = 25 // two /25 chunks; the sizer asks for a /24
	f.r.st = &panickingLeaseStore{fakeStore: f.fs}
	runID := f.runNow(t)

	assert.Equal(t, store.RunFailed, f.fs.runStatus(runID))
	statuses := map[string]int{}
	for _, c := range f.fs.chunksOf(runID) {
		statuses[c.status]++
	}
	assert.Equal(t, map[string]int{store.ChunkFailed: 1, store.ChunkPending: 1}, statuses)
}

// panickingLeaseStore panics on the second LeaseChunk call.
type panickingLeaseStore struct {
	*fakeStore
	calls int
}

func (s *panickingLeaseStore) LeaseChunk(ctx context.Context, runID int64) (store.Chunk, bool, error) {
	s.calls++
	if s.calls == 2 {
		panic("lease exploded")
	}
	return s.fakeStore.LeaseChunk(ctx, runID)
}

// A panic while retrying a stale run is contained; the run stays stale.
func TestRetryStalePanicContained(t *testing.T) {
	f := setup(t, model.Target{Kind: model.TargetCIDR, Value: "10.20.0.0/24"})
	f.fs.finishFails = 1
	runID := f.runNow(t)
	f.r.st = &panickingFinishStore{fakeStore: f.fs}

	f.r.Tick(context.Background(), time.Now())
	f.r.Wait()
	assert.True(t, f.r.isStale(runID))
	assert.Equal(t, store.RunRunning, f.fs.runStatus(runID))
}

type panickingFinishStore struct{ *fakeStore }

func (s *panickingFinishStore) FinishRun(context.Context, int64, string, time.Duration) (bool, error) {
	panic("finish exploded")
}
