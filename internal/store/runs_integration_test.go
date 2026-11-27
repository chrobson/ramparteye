//go:build integration

package store_test

import (
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/ctx42/testing/pkg/assert"
	"github.com/ctx42/testing/pkg/must"

	"github.com/chrobson/ramparteye/internal/model"
	"github.com/chrobson/ramparteye/internal/store"
)

func TestRunLifecycle(t *testing.T) {
	s, pool := newStore(t)
	cfgID := must.Value(s.CreateScanConfig(ctx, store.ScanConfig{Name: "c", TopPorts: 10, MaxRate: 10, Workers: 1}))
	chunks := []netip.Prefix{
		netip.MustParsePrefix("10.20.0.0/24"), netip.MustParsePrefix("10.20.1.0/24"),
		netip.MustParsePrefix("10.20.2.5/32"),
	}
	runID := must.Value(s.CreateRun(ctx, &cfgID, chunks))
	assert.True(t, must.Value(s.StartRun(ctx, runID)))

	// Concurrent leases never return the same chunk.
	var mu sync.Mutex
	seen := map[int64]bool{}
	var wg sync.WaitGroup
	for range 6 {
		wg.Go(func() {
			c, ok, err := s.LeaseChunk(ctx, runID)
			assert.NoError(t, err)
			if ok {
				mu.Lock()
				assert.False(t, seen[c.ID])
				seen[c.ID] = true
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	assert.Len(t, 3, seen)

	// A crash: every chunk back to pending, the run paused.
	assert.Equal(t, int64(3), must.Value(s.ResetRunning(ctx)))
	open := must.Value(s.OpenRuns(ctx))
	assert.Len(t, 1, open)
	assert.Equal(t, store.RunPaused, open[0].Status)

	ip := addr("10.20.0.10")
	for {
		c, ok, err := s.LeaseChunk(ctx, runID)
		assert.NoError(t, err)
		if !ok {
			break
		}
		assert.Equal(t, 2, c.Attempts)
		switch c.Prefix.String() {
		case "10.20.0.0/24":
			hosts := []model.HostObs{{IP: ip, Up: true}}
			svcs := []model.ServiceObs{{Key: model.AssetKey{IP: ip, Port: 80, Proto: "tcp"},
				Product: "nginx", Version: "1.27.3", Banner: "http"}}
			assert.NoError(t, s.CompleteChunk(ctx, c, 1500*time.Millisecond, hosts, svcs))
			assert.NoError(t, s.InsertObservations(ctx, runID, hosts, svcs)) // idempotent
		case "10.20.1.0/24":
			assert.NoError(t, s.ReleaseChunk(ctx, c, "interrupted"))
			c2, ok, _ := s.LeaseChunk(ctx, runID)
			assert.True(t, ok)
			assert.Equal(t, c.ID, c2.ID)
			// An interruption refunds the lease's attempt.
			assert.NoError(t, s.InterruptChunk(ctx, c2, "window ended"))
			c3, ok, _ := s.LeaseChunk(ctx, runID)
			assert.True(t, ok)
			assert.Equal(t, c2.Attempts, c3.Attempts)
			assert.NoError(t, s.FailChunk(ctx, c3, "nmap exit 1"))
		default:
			assert.NoError(t, s.CompleteChunk(ctx, c, time.Second, []model.HostObs{{IP: c.Prefix.Addr()}}, nil))
		}
	}
	assert.Equal(t, store.ChunkCounts{Done: 2, Failed: 1}, must.Value(s.CountChunks(ctx, runID)))
	assert.True(t, must.Value(s.FinishRun(ctx, runID, store.RunDone, 2*time.Second)))

	run := must.Value(s.Run(ctx, runID))
	assert.Equal(t, store.RunDone, run.Status)
	assert.Equal(t, int64(2000), *run.DurationMS)
	assert.NotNil(t, run.FinishedAt)
	assert.Equal(t, "c", run.ConfigName)
	assert.Equal(t, 3, run.ChunksTotal)
	assert.Equal(t, 2, run.ChunksDone)
	assert.Equal(t, 1, run.ChunksFailed)
	assert.Equal(t, 1, run.HostsUp)
	assert.Equal(t, 1, run.Services)

	var hostsUp, chunkMS int64
	must.Nil(pool.QueryRow(ctx, `SELECT hosts_up, duration_ms FROM scan_chunks
		WHERE run_id = $1 AND cidr = '10.20.0.0/24'`, runID).Scan(&hostsUp, &chunkMS))
	assert.Equal(t, int64(1), hostsUp)
	assert.Equal(t, int64(1500), chunkMS)

	last := must.Value(s.LastRun(ctx, cfgID))
	assert.Equal(t, runID, last.ID)
	assert.NotNil(t, last.StartedAt)
	assert.Nil(t, must.Value(s.LastRun(ctx, -1)))
	assert.Len(t, 1, must.Value(s.Runs(ctx, 10)))
	assert.Equal(t, runID, must.Value(s.LatestDoneRun(ctx)))
	_, err := s.Run(ctx, -1)
	assert.ErrorIs(t, store.ErrRunNotFound, err)
}

func TestCancelRuns(t *testing.T) {
	s, _ := newStore(t)
	a := must.Value(s.CreateRun(ctx, nil, nil))
	b := must.Value(s.CreateRun(ctx, nil, nil))

	assert.False(t, must.Value(s.CancelRequested(ctx, a)))
	assert.NoError(t, s.RequestCancel(ctx, []int64{a, b}, nil))
	assert.NoError(t, s.RequestCancel(ctx, []int64{a}, nil)) // repeated request is fine
	assert.True(t, must.Value(s.CancelRequested(ctx, a)))
	assert.True(t, must.Value(s.CancelRequested(ctx, b)))

	assert.True(t, must.Value(s.FinishRun(ctx, a, store.RunCancelled, time.Second)))
	run := must.Value(s.Run(ctx, a))
	assert.Equal(t, store.RunCancelled, run.Status)
	assert.NotNil(t, run.FinishedAt)
	// A queued or paused run with a cancel request is never resumed; a
	// running one stays listed so its profile is seen busy.
	assert.Len(t, 0, must.Value(s.OpenRuns(ctx)))
	assert.True(t, must.Value(s.StartRun(ctx, b)))
	open := must.Value(s.OpenRuns(ctx))
	assert.Len(t, 1, open)
	assert.Equal(t, b, open[0].ID)
}

// A final status is never overwritten: neither a late FinishRun nor
// StartRun changes a done, failed or cancelled run.
func TestFinishRunKeepsFinalStatus(t *testing.T) {
	s, _ := newStore(t)
	for _, final := range []string{store.RunDone, store.RunFailed, store.RunCancelled} {
		id := must.Value(s.CreateRun(ctx, nil, nil))
		assert.True(t, must.Value(s.StartRun(ctx, id)))
		assert.True(t, must.Value(s.FinishRun(ctx, id, final, time.Second)))

		assert.False(t, must.Value(s.FinishRun(ctx, id, store.RunPaused, time.Second)))
		assert.False(t, must.Value(s.FinishRun(ctx, id, store.RunDone, time.Second)))
		assert.False(t, must.Value(s.StartRun(ctx, id)))
		run := must.Value(s.Run(ctx, id))
		assert.Equal(t, final, run.Status)
		assert.Equal(t, int64(1000), *run.DurationMS)
		assert.NotNil(t, run.FinishedAt)
	}
	// A paused run can be finished later.
	id := must.Value(s.CreateRun(ctx, nil, nil))
	assert.True(t, must.Value(s.FinishRun(ctx, id, store.RunPaused, time.Second)))
	assert.True(t, must.Value(s.StartRun(ctx, id)))
	assert.True(t, must.Value(s.FinishRun(ctx, id, store.RunDone, time.Second)))
	_, err := s.FinishRun(ctx, -1, store.RunDone, 0)
	assert.NoError(t, err)
}

// CancelOpenRuns requests a cancel for every unfinished scan run and marks the ones not running cancelled at once; a running run
// is left to the process executing it.
func TestCancelOpenRuns(t *testing.T) {
	s, pool := newStore(t)
	queued := must.Value(s.CreateRun(ctx, nil, nil))
	running := must.Value(s.CreateRun(ctx, nil, nil))
	assert.True(t, must.Value(s.StartRun(ctx, running)))
	done := must.Value(s.CreateRun(ctx, nil, nil))
	assert.True(t, must.Value(s.FinishRun(ctx, done, store.RunDone, 0)))
	imported := insertRun(t, pool, "import", store.RunRunning)
	uid := must.Value(s.CreateUser(ctx, model.NewUser{Login: "op", PasswordHash: "h", Role: "Admin"}))

	requested, finished, err := s.CancelOpenRuns(ctx, &uid)

	assert.NoError(t, err)
	assert.Equal(t, []int64{queued, running}, requested)
	assert.Equal(t, []int64{queued}, finished)
	for _, id := range []int64{queued} {
		run := must.Value(s.Run(ctx, id))
		assert.Equal(t, store.RunCancelled, run.Status)
		assert.NotNil(t, run.FinishedAt)
	}
	assert.Equal(t, store.RunRunning, must.Value(s.Run(ctx, running)).Status)
	assert.Equal(t, store.RunDone, must.Value(s.Run(ctx, done)).Status)
	assert.Equal(t, store.RunRunning, must.Value(s.Run(ctx, imported)).Status)
	for _, id := range requested {
		assert.True(t, must.Value(s.CancelRequested(ctx, id)))
	}
	assert.False(t, must.Value(s.CancelRequested(ctx, done)))
	var by int64
	must.Nil(pool.QueryRow(ctx, `SELECT requested_by FROM run_cancel_requests WHERE run_id = $1`, running).Scan(&by))
	assert.Equal(t, uid, by)
	open := must.Value(s.OpenRuns(ctx)) // the running one stays visible
	assert.Len(t, 1, open)
	assert.Equal(t, running, open[0].ID)

	// Again: only the still running run, already requested (idempotent).
	requested, finished, err = s.CancelOpenRuns(ctx, nil)
	assert.NoError(t, err)
	assert.Equal(t, []int64{running}, requested)
	assert.Len(t, 0, finished)

	// Nothing open: nothing requested.
	assert.True(t, must.Value(s.FinishRun(ctx, running, store.RunCancelled, 0)))
	requested, finished, err = s.CancelOpenRuns(ctx, nil)
	assert.NoError(t, err)
	assert.Len(t, 0, requested)
	assert.Len(t, 0, finished)
}

// After a crash a run with a cancel request is marked cancelled instead of
// paused, so it is never resumed.
func TestResetRunningCancelsRequestedRuns(t *testing.T) {
	s, _ := newStore(t)
	p := []netip.Prefix{netip.MustParsePrefix("10.20.0.0/24")}
	cancelled := must.Value(s.CreateRun(ctx, nil, p))
	kept := must.Value(s.CreateRun(ctx, nil, p))
	for _, id := range []int64{cancelled, kept} {
		assert.True(t, must.Value(s.StartRun(ctx, id)))
		lease(t, s, id)
	}
	assert.NoError(t, s.RequestCancel(ctx, []int64{cancelled}, nil))

	assert.Equal(t, int64(2), must.Value(s.ResetRunning(ctx)))

	run := must.Value(s.Run(ctx, cancelled))
	assert.Equal(t, store.RunCancelled, run.Status)
	assert.NotNil(t, run.FinishedAt)
	open := must.Value(s.OpenRuns(ctx))
	assert.Len(t, 1, open)
	assert.Equal(t, kept, open[0].ID)
	assert.Equal(t, store.RunPaused, open[0].Status)
}

// The time machine lists finished runs only and steps between them,
// imports included, skipping unfinished, failed and cancelled runs.
func TestDoneRunsAndNeighbours(t *testing.T) {
	s, pool := newStore(t)
	first := insertRun(t, pool, "scan", store.RunDone)
	failed := insertRun(t, pool, "scan", store.RunFailed)
	imp := insertRun(t, pool, "import", store.RunDone)
	cancelled := insertRun(t, pool, "scan", store.RunCancelled)
	last := insertRun(t, pool, "scan", store.RunDone)
	running := insertRun(t, pool, "scan", store.RunRunning)

	runs := must.Value(s.DoneRuns(ctx, 10))
	var ids []int64
	for _, r := range runs {
		ids = append(ids, r.ID)
		assert.Equal(t, store.RunDone, r.Status)
	}
	assert.Equal(t, []int64{last, imp, first}, ids)
	assert.Equal(t, "import", runs[1].Kind)
	assert.Len(t, 2, must.Value(s.DoneRuns(ctx, 2)))

	for _, tc := range []struct {
		run, prev, next int64
	}{
		{first, 0, imp},
		{imp, first, last},
		{last, imp, 0},
		{failed, first, imp},
		{cancelled, imp, last},
		{running, last, 0},
	} {
		prev, next, err := s.AdjacentDoneRuns(ctx, tc.run)
		assert.NoError(t, err)
		assert.Equal(t, tc.prev, prev)
		assert.Equal(t, tc.next, next)
	}
}
