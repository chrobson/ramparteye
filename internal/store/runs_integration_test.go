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
	assert.NoError(t, s.StartRun(ctx, runID))

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
	assert.NoError(t, s.FinishRun(ctx, runID, store.RunDone, 2*time.Second))

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

func TestStopResumeRun(t *testing.T) {
	s, _ := newStore(t)
	runID := must.Value(s.CreateRun(ctx, nil, nil))

	assert.True(t, must.Value(s.StopRun(ctx, runID)))
	assert.Len(t, 0, must.Value(s.OpenRuns(ctx)))
	assert.True(t, must.Value(s.ResumeRun(ctx, runID)))
	assert.Len(t, 1, must.Value(s.OpenRuns(ctx)))
	assert.False(t, must.Value(s.ResumeRun(ctx, runID)))
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

	assert.NoError(t, s.FinishRun(ctx, a, store.RunCancelled, time.Second))
	run := must.Value(s.Run(ctx, a))
	assert.Equal(t, store.RunCancelled, run.Status)
	assert.NotNil(t, run.FinishedAt)
	assert.Len(t, 1, must.Value(s.OpenRuns(ctx)))
}
