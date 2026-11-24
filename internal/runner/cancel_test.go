package runner

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/ctx42/testing/pkg/assert"
	"github.com/ctx42/testing/pkg/must"

	"github.com/chrobson/ramparteye/internal/model"
	"github.com/chrobson/ramparteye/internal/store"
)

// waitFor polls cond until it holds or d elapsed; false on timeout.
func waitFor(d time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(2 * time.Millisecond)
	}
	return cond()
}

// waitDone waits for every run of the runner to stop; false after d.
func waitDone(r *Runner, d time.Duration) bool {
	done := make(chan struct{})
	go func() {
		r.Wait()
		close(done)
	}()
	select {
	case <-done:
		return true
	case <-time.After(d):
		return false
	}
}

// startBlocked starts a manual run whose only chunk blocks in Discover until
// its context ends, and returns once nmap "runs".
func startBlocked(t *testing.T, f *fixture) int64 {
	t.Helper()
	f.sc.setBlock(pfx("10.20.0.0/24"), true)
	f.sc.started = make(chan netip.Prefix, 8)
	runID := must.Value(f.r.Start(context.Background(), f.cfg.ID))
	select {
	case <-f.sc.started:
	case <-time.After(5 * time.Second):
		t.Fatal("scanner never started")
	}
	return runID
}

func TestCancelAllKillsWithin5s(t *testing.T) {
	f := setup(t, model.Target{Kind: model.TargetCIDR, Value: "10.20.0.0/24"})
	runID := startBlocked(t, f)
	scanCtx := f.sc.contexts()[0]

	start := time.Now()
	ids, err := f.r.CancelAll(context.Background(), 7)

	assert.NoError(t, err)
	assert.Equal(t, []int64{runID}, ids)
	select {
	case <-scanCtx.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("scanner context not cancelled within 5 s")
	}
	assert.True(t, waitDone(f.r, 5*time.Second))
	assert.True(t, time.Since(start) < 5*time.Second)
	assert.Equal(t, store.RunCancelled, f.fs.runStatus(runID))
	// The interrupted chunk is not counted as an attempt and never resumed.
	assert.Equal(t, store.ChunkPending, f.fs.chunksOf(runID)[0].status)
	f.r.Tick(context.Background(), time.Now())
	f.r.Wait()
	assert.Equal(t, 1, f.sc.discoverCount())
	assert.Equal(t, store.RunCancelled, f.fs.runStatus(runID))
}

// A cancelled run reports "cancelled" to OnRunDone (which drives the
// DefectDojo push, done runs only) and its diff is never applied, whether
// it is cancelled while scanning or during post-processing.
func TestCancelledRunSkipsDiffAndDojo(t *testing.T) {
	t.Run("while scanning", func(t *testing.T) {
		f := setup(t, model.Target{Kind: model.TargetCIDR, Value: "10.20.0.0/24"})
		h := &hookRecorder{}
		f.r.OnRunDone = h.hook
		startBlocked(t, f)

		_, err := f.r.CancelAll(context.Background(), 1)

		assert.NoError(t, err)
		assert.True(t, waitDone(f.r, 5*time.Second))
		assert.Equal(t, []string{store.RunCancelled}, h.got())
		assert.Len(t, 0, f.fs.appliedRuns())
	})

	t.Run("during post-processing", func(t *testing.T) {
		f, _ := pipelineFixture(t, headerSig)
		h := &hookRecorder{}
		f.r.OnRunDone = h.hook
		f.fp.block = true        // the HTTP probe hangs until its context ends
		f.fp.timeout = time.Hour // far beyond the test
		runID := must.Value(f.r.Start(context.Background(), f.cfg.ID))
		assert.True(t, waitFor(5*time.Second, func() bool { return len(f.fp.endpoints()) > 0 }))

		ids, err := f.r.CancelAll(context.Background(), 1)

		assert.NoError(t, err)
		assert.Equal(t, []int64{runID}, ids)
		assert.True(t, waitDone(f.r, 5*time.Second))
		assert.Equal(t, store.RunCancelled, f.fs.runStatus(runID))
		assert.Equal(t, []string{store.RunCancelled}, h.got())
		assert.Len(t, 0, f.fs.appliedRuns())
	})
}

func TestCancelledRunHasReceipt(t *testing.T) {
	f := setup(t, model.Target{Kind: model.TargetCIDR, Value: "10.20.0.0/24"})
	ch, unsubscribe := f.r.Subscribe()
	defer unsubscribe()
	runID := startBlocked(t, f)

	_, err := f.r.CancelAll(context.Background(), 1)
	assert.NoError(t, err)
	events := collect(t, ch, runID)
	assert.True(t, waitDone(f.r, 5*time.Second))

	rc, err := f.fs.SafetyReceipt(context.Background(), runID)
	assert.NoError(t, err)
	assert.Equal(t, 1, rc.NmapInvocations) // the killed invocation is metered
	assert.Equal(t, int64(10), rc.NmapPackets)
	last := events[len(events)-1]
	assert.Equal(t, EventFinished, last.Kind)
	assert.Contain(t, "cancelled; safety", last.Message)
}

func TestCancelAllNoRunning(t *testing.T) {
	f := setup(t, model.Target{Kind: model.TargetCIDR, Value: "10.20.0.0/24"})

	ids, err := f.r.CancelAll(context.Background(), 3)

	assert.NoError(t, err)
	assert.Len(t, 0, ids)
	audits := f.fs.auditLog()
	assert.Len(t, 1, audits)
	assert.Equal(t, "scans.cancel_all", audits[0].action)
}

// The audit entry names the user and the runs.
func TestCancelAllAudit(t *testing.T) {
	f := setup(t, model.Target{Kind: model.TargetCIDR, Value: "10.20.0.0/24"})
	runID := startBlocked(t, f)

	_, err := f.r.CancelAll(context.Background(), 3)
	assert.NoError(t, err)
	f.r.Wait()

	audits := f.fs.auditLog()
	assert.Len(t, 1, audits)
	a := audits[0]
	assert.Equal(t, "scans.cancel_all", a.action)
	assert.Equal(t, "scan_runs", a.entity)
	assert.Equal(t, int64(3), *a.userID)
	assert.Equal(t, map[string]any{"requested": []int64{runID}}, a.details)
	by, ok := f.fs.cancelReqs[runID]
	assert.True(t, ok)
	assert.Equal(t, int64(3), *by)

	// A system cancel (by 0) has no actor.
	f = setup(t)
	_, err = f.r.CancelAll(context.Background(), 0)
	assert.NoError(t, err)
	assert.Nil(t, f.fs.auditLog()[0].userID)
}

// Queued and paused runs not executing anywhere are cancelled at once and
// get OnRunDone; the scheduler never resumes them.
func TestCancelAllFinishesIdleRuns(t *testing.T) {
	f := setup(t, model.Target{Kind: model.TargetCIDR, Value: "10.20.0.0/24"})
	h := &hookRecorder{}
	f.r.OnRunDone = h.hook
	ctx := context.Background()
	paused := must.Value(f.r.createRun(ctx, f.cfg))
	f.fs.setStatus(paused, store.RunPaused)

	ids, err := f.r.CancelAll(ctx, 1)

	assert.NoError(t, err)
	assert.Equal(t, []int64{paused}, ids)
	assert.Equal(t, store.RunCancelled, f.fs.runStatus(paused))
	assert.Equal(t, []string{store.RunCancelled}, h.got())
	f.r.Tick(ctx, time.Now())
	f.r.Wait()
	assert.Equal(t, 0, f.sc.discoverCount())
	assert.Equal(t, []string{store.RunCancelled}, h.got())
}

// A cancel requested by another process (a run_cancel_requests row) is
// honoured at the next chunk boundary: the run ends cancelled, its other
// chunks are not scanned and its diff is not applied.
func TestCancelRequestFromOtherProcess(t *testing.T) {
	f := setup(t, model.Target{Kind: model.TargetCIDR, Value: "10.20.0.0/22"}) // 4 chunks
	f.fs.configs[0].Workers = 1
	h := &hookRecorder{}
	f.r.OnRunDone = h.hook
	f.sc.onCall = func() { // while the first chunk is scanned
		last := must.Value(f.fs.LastRun(context.Background(), f.cfg.ID))
		f.fs.requestCancel(last.ID)
	}
	runID := must.Value(f.r.Start(context.Background(), f.cfg.ID))
	assert.True(t, waitDone(f.r, 5*time.Second))

	assert.Equal(t, store.RunCancelled, f.fs.runStatus(runID))
	assert.Equal(t, []string{store.RunCancelled}, h.got())
	assert.Len(t, 0, f.fs.appliedRuns())
	pending := 0
	for _, c := range f.fs.chunksOf(runID) {
		if c.status == store.ChunkPending {
			pending++
		}
	}
	assert.Equal(t, 3, pending)
	assert.Equal(t, 1, f.sc.discoverCount())
}

// A run whose cancel request arrives while it is paused by its window ends
// cancelled instead of paused, so it does not linger.
func TestCancelRequestedWhilePausing(t *testing.T) {
	f := setup(t, model.Target{Kind: model.TargetCIDR, Value: "10.20.0.0/24"})
	runID := startBlocked(t, f)
	f.fs.requestCancel(runID)
	f.r.Stop(runID) // window end or stop

	assert.True(t, waitDone(f.r, 5*time.Second))
	assert.Equal(t, store.RunCancelled, f.fs.runStatus(runID))
}

// A run launched here between CancelAll's first sweep of the active runs
// and the stored cancel requests is cancelled at once too, not only at its
// next chunk boundary.
func TestCancelAllCatchesLateLaunch(t *testing.T) {
	f := setup(t, model.Target{Kind: model.TargetCIDR, Value: "10.20.0.0/24"})
	f.sc.setBlock(pfx("10.20.0.0/24"), true)
	f.sc.started = make(chan netip.Prefix, 8)
	var runID int64
	f.fs.onCancel = func() {
		f.fs.onCancel = nil
		runID = must.Value(f.r.Start(context.Background(), f.cfg.ID))
		<-f.sc.started // running, nmap blocked
	}

	ids, err := f.r.CancelAll(context.Background(), 1)

	assert.NoError(t, err)
	assert.Equal(t, []int64{runID}, ids)
	assert.True(t, waitDone(f.r, 5*time.Second))
	assert.Equal(t, store.RunCancelled, f.fs.runStatus(runID))
}

// A run running in another process keeps its profile occupied while its
// cancel request is pending: the scheduler starts no second run.
func TestCancelRequestedRunElsewhereOccupiesProfile(t *testing.T) {
	f := setup(t, model.Target{Kind: model.TargetCIDR, Value: "10.20.0.0/24"})
	f.fs.configs[0].EveryMinutes = ptr(1)
	ctx := context.Background()
	runID := must.Value(f.r.createRun(ctx, f.fs.configs[0]))
	assert.True(t, must.Value(f.fs.StartRun(ctx, runID)))
	f.fs.requestCancel(runID)

	f.r.Tick(ctx, time.Now().Add(time.Hour))
	f.r.Wait()

	assert.Equal(t, 1, f.fs.runCount())
	assert.Equal(t, 0, f.sc.discoverCount())
}

// The attempt is audited even when the cancel requests cannot be stored;
// runs executing here are still cancelled.
func TestCancelAllStoreFailure(t *testing.T) {
	f := setup(t, model.Target{Kind: model.TargetCIDR, Value: "10.20.0.0/24"})
	runID := startBlocked(t, f)
	f.fs.cancelFail = true

	ids, err := f.r.CancelAll(context.Background(), 2)

	assert.Error(t, err)
	assert.Equal(t, []int64{runID}, ids)
	assert.True(t, waitDone(f.r, 5*time.Second))
	assert.Equal(t, store.RunCancelled, f.fs.runStatus(runID))
	audits := f.fs.auditLog()
	assert.Len(t, 1, audits)
	assert.Equal(t, AuditCancelAll, audits[0].action)
	d := audits[0].details.(map[string]any)
	assert.Equal(t, []int64{runID}, d["requested"])
	assert.Contain(t, "database unavailable", d["error"].(string))
}

// A session whose run is cancelled before it started settles cancelled
// (never "paused; start: context canceled"); a run already cancelled in the
// store is not started at all.
func TestCancelledBeforeStart(t *testing.T) {
	f := setup(t, model.Target{Kind: model.TargetCIDR, Value: "10.20.0.0/24"})
	h := &hookRecorder{}
	f.r.OnRunDone = h.hook
	ctx := context.Background()
	runID := must.Value(f.r.createRun(ctx, f.cfg))
	c := newControl(ctx, time.Time{})
	c.cancel(ErrRunCancelled)
	f.r.execute(c, runID, f.cfg, time.Time{})
	assert.Equal(t, store.RunCancelled, f.fs.runStatus(runID))
	assert.Equal(t, 0, f.sc.discoverCount())
	assert.Equal(t, []string{store.RunCancelled}, h.got())

	runID = must.Value(f.r.createRun(ctx, f.cfg))
	f.fs.setStatus(runID, store.RunCancelled) // CancelAll got there first
	f.r.execute(newControl(ctx, time.Time{}), runID, f.cfg, time.Time{})
	assert.Equal(t, store.RunCancelled, f.fs.runStatus(runID))
	assert.Equal(t, 0, f.sc.discoverCount())
	assert.Len(t, 1, h.got())
}
