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

func ptr[T any](v T) *T { return &v }

func TestDue(t *testing.T) {
	now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	every := store.ScanConfig{EveryMinutes: ptr(60)}
	assert.False(t, Due(now, store.ScanConfig{}, nil))                     // manual profile
	assert.False(t, Due(now, store.ScanConfig{EveryMinutes: ptr(0)}, nil)) // manual profile
	assert.True(t, Due(now, every, nil))                                   // never ran
	assert.False(t, Due(now, every, &store.RunInfo{StartedAt: ptr(now.Add(-59 * time.Minute))}))
	assert.True(t, Due(now, every, &store.RunInfo{StartedAt: ptr(now.Add(-60 * time.Minute))}))
	assert.True(t, Due(now, every, &store.RunInfo{})) // queued, never started
}

func TestTickStartsPausesResumes(t *testing.T) {
	f := setup(t, model.Target{Kind: model.TargetCIDR, Value: "10.20.0.0/23"})
	f.fs.configs[0].Workers = 1
	f.fs.configs[0].EveryMinutes = ptr(60)
	f.fs.configs[0].WindowStart = ptr(22 * time.Hour)
	f.fs.configs[0].WindowEnd = ptr(6 * time.Hour)
	blocked := pfx("10.20.0.0/24")
	f.sc.setBlock(blocked, true)
	f.sc.started = make(chan netip.Prefix, 16)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// The window end becomes the run's context deadline, so the simulated
	// day must lie in the future.
	day := time.Now().AddDate(0, 0, 1)
	outside := time.Date(day.Year(), day.Month(), day.Day(), 12, 0, 0, 0, time.Local)
	inside := time.Date(day.Year(), day.Month(), day.Day(), 23, 0, 0, 0, time.Local)

	// Outside the window nothing starts.
	f.r.Tick(ctx, outside)
	assert.Equal(t, 0, f.fs.runCount())

	// Inside: a run starts and blocks on its first chunk.
	f.r.Tick(ctx, inside)
	assert.Equal(t, 1, f.fs.runCount())
	<-f.sc.started
	// Another tick while it runs starts nothing.
	f.r.Tick(ctx, inside.Add(time.Minute))
	assert.Equal(t, 1, f.fs.runCount())
	assert.Len(t, 1, f.r.ActiveRuns())
	runID := f.r.ActiveRuns()[0]

	// Leaving the window pauses it; the chunk goes back to pending.
	f.r.Tick(ctx, inside.Add(8*time.Hour))
	f.r.Wait()
	assert.Equal(t, store.RunPaused, f.fs.runStatus(runID))

	// The next window resumes the same run and finishes it.
	f.sc.setBlock(blocked, false)
	f.r.Tick(ctx, inside.Add(24*time.Hour))
	f.r.Wait()
	assert.Equal(t, 1, f.fs.runCount())
	assert.Equal(t, store.RunDone, f.fs.runStatus(runID))
	// The blocked chunk was leased twice; its interruption cost no attempt.
	for _, c := range f.fs.chunksOf(runID) {
		assert.Equal(t, 1, c.Attempts)
	}
}

func TestTickWindowDeadline(t *testing.T) {
	f := setup(t, model.Target{Kind: model.TargetCIDR, Value: "10.20.0.0/24"})
	f.fs.configs[0].EveryMinutes = ptr(5)
	f.sc.setBlock(pfx("10.20.0.0/24"), true)
	// The window ends 150 ms from now: the run must stop by its own deadline.
	now := time.Now()
	midnight := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	start := now.Add(-time.Minute).Sub(midnight)
	end := now.Add(150 * time.Millisecond).Sub(midnight)
	if end >= 24*time.Hour || start < 0 {
		t.Skip("too close to midnight")
	}
	f.fs.configs[0].WindowStart, f.fs.configs[0].WindowEnd = &start, &end
	f.r.Tick(context.Background(), now)

	done := make(chan struct{})
	go func() { f.r.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("run did not stop at window end")
	}
	assert.Equal(t, 1, f.fs.runCount())
	for id := range f.fs.runs {
		assert.Equal(t, store.RunPaused, f.fs.runStatus(id))
	}
	// The scheduled run's receipt carries its window.
	rc, err := f.fs.SafetyReceipt(context.Background(), 1)
	assert.NoError(t, err)
	assert.NotEmpty(t, rc.TimeWindow)
}

func TestTickDisabledAndManual(t *testing.T) {
	f := setup(t, model.Target{Kind: model.TargetCIDR, Value: "10.20.0.0/24"})
	f.fs.configs[0].Enabled = false
	f.fs.configs[0].EveryMinutes = ptr(1)
	f.r.Tick(context.Background(), time.Now())
	f.fs.configs[0].Enabled = true
	f.fs.configs[0].EveryMinutes = nil
	f.r.Tick(context.Background(), time.Now())
	f.r.Wait()
	assert.Equal(t, 0, f.fs.runCount())
}

func TestTickNotDueYet(t *testing.T) {
	f := setup(t, model.Target{Kind: model.TargetCIDR, Value: "10.20.0.0/24"})
	f.fs.configs[0].EveryMinutes = ptr(60)
	now := time.Now()
	f.r.Tick(context.Background(), now)
	f.r.Wait()
	assert.Equal(t, 1, f.fs.runCount())
	f.r.Tick(context.Background(), now.Add(30*time.Minute))
	f.r.Wait()
	assert.Equal(t, 1, f.fs.runCount())
}

func TestTickKeepsManualRunOutsideWindow(t *testing.T) {
	f := setup(t, model.Target{Kind: model.TargetCIDR, Value: "10.20.0.0/24"})
	f.fs.configs[0].WindowStart = ptr(22 * time.Hour)
	f.fs.configs[0].WindowEnd = ptr(6 * time.Hour)
	f.sc.setBlock(pfx("10.20.0.0/24"), true)
	f.sc.started = make(chan netip.Prefix, 4)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runID, err := f.r.Start(ctx, f.cfg.ID)
	assert.NoError(t, err)
	<-f.sc.started
	f.r.Tick(ctx, time.Date(2026, 11, 21, 12, 0, 0, 0, time.Local))
	assert.Equal(t, []int64{runID}, f.r.ActiveRuns())
	f.r.Stop(runID)
	f.r.Wait()
	assert.Equal(t, store.RunPaused, f.fs.runStatus(runID))
}

// A run marked running that does not execute in this process belongs to
// another live process: the scheduler leaves its profile alone.
func TestTickLeavesRunsOfOtherProcesses(t *testing.T) {
	f := setup(t, model.Target{Kind: model.TargetCIDR, Value: "10.20.0.0/24"})
	f.fs.configs[0].EveryMinutes = ptr(1)
	ctx := context.Background()
	runID, err := f.r.createRun(ctx, f.fs.configs[0])
	assert.NoError(t, err)
	assert.True(t, must.Value(f.fs.StartRun(ctx, runID)))
	f.r.Tick(ctx, time.Now().Add(time.Hour))
	f.r.Wait()
	assert.Equal(t, 1, f.fs.runCount())
	assert.Equal(t, store.RunRunning, f.fs.runStatus(runID))
}
