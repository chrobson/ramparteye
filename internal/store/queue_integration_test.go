//go:build integration

package store_test

import (
	"net/netip"
	"testing"
	"time"

	"github.com/ctx42/testing/pkg/assert"
	"github.com/ctx42/testing/pkg/must"

	"github.com/chrobson/ramparteye/internal/model"
	"github.com/chrobson/ramparteye/internal/store"
)

// A worker whose lease was taken away (ResetRunning, then a new lease) must
// not complete, release, fail or interrupt the chunk it no longer owns.
func TestChunkLeaseGuard(t *testing.T) {
	s, _ := newStore(t)
	runID := must.Value(s.CreateRun(ctx, nil, []netip.Prefix{netip.MustParsePrefix("10.20.0.0/24")}))

	stale, ok, err := s.LeaseChunk(ctx, runID)
	assert.NoError(t, err)
	assert.True(t, ok)
	assert.Equal(t, int64(1), must.Value(s.ResetRunning(ctx)))
	fresh, ok, err := s.LeaseChunk(ctx, runID)
	assert.NoError(t, err)
	assert.True(t, ok)
	assert.Equal(t, stale.ID, fresh.ID)
	assert.Equal(t, stale.Attempts+1, fresh.Attempts)

	hosts := []model.HostObs{{IP: addr("10.20.0.9"), Up: true}}
	assert.ErrorIs(t, store.ErrLeaseLost, s.CompleteChunk(ctx, stale, time.Second, hosts, nil))
	assert.ErrorIs(t, store.ErrLeaseLost, s.ReleaseChunk(ctx, stale, "boom"))
	assert.ErrorIs(t, store.ErrLeaseLost, s.FailChunk(ctx, stale, "boom"))
	assert.ErrorIs(t, store.ErrLeaseLost, s.InterruptChunk(ctx, stale, "window ended"))
	// The refused completion stored nothing.
	assert.Len(t, 0, must.Value(s.RunHostObs(ctx, runID)))
	assert.Equal(t, store.ChunkCounts{Running: 1}, must.Value(s.CountChunks(ctx, runID)))

	assert.NoError(t, s.CompleteChunk(ctx, fresh, time.Second, hosts, nil))
	// A finished chunk is no longer leased by anyone.
	assert.ErrorIs(t, store.ErrLeaseLost, s.CompleteChunk(ctx, fresh, time.Second, hosts, nil))
	assert.ErrorIs(t, store.ErrLeaseLost, s.ReleaseChunk(ctx, fresh, "late"))
	assert.Equal(t, store.ChunkCounts{Done: 1}, must.Value(s.CountChunks(ctx, runID)))
	assert.Len(t, 1, must.Value(s.RunHostObs(ctx, runID)))
}

// ResetRunning is global: it assumes no other process is executing scans
// (it runs once when `serve` starts). The lease guard keeps a violation of
// that assumption safe, see TestChunkLeaseGuard.
func TestResetRunningIsGlobal(t *testing.T) {
	s, _ := newStore(t)
	a := must.Value(s.CreateRun(ctx, nil, []netip.Prefix{netip.MustParsePrefix("10.20.0.0/24")}))
	b := must.Value(s.CreateRun(ctx, nil, []netip.Prefix{netip.MustParsePrefix("10.20.1.0/24")}))
	for _, id := range []int64{a, b} {
		assert.True(t, must.Value(s.StartRun(ctx, id)))
		_, ok, err := s.LeaseChunk(ctx, id)
		assert.NoError(t, err)
		assert.True(t, ok)
	}
	assert.Equal(t, int64(2), must.Value(s.ResetRunning(ctx)))
	for _, r := range must.Value(s.OpenRuns(ctx)) {
		assert.Equal(t, store.RunPaused, r.Status)
	}
}

func TestReleaseInterruptFail(t *testing.T) {
	s, _ := newStore(t)
	runID := must.Value(s.CreateRun(ctx, nil, []netip.Prefix{netip.MustParsePrefix("10.20.0.0/24")}))

	c := lease(t, s, runID)
	assert.NoError(t, s.ReleaseChunk(ctx, c, "nmap exit 1"))
	c = lease(t, s, runID)
	assert.Equal(t, 2, c.Attempts)
	assert.NoError(t, s.InterruptChunk(ctx, c, "window ended"))
	c = lease(t, s, runID)
	assert.Equal(t, 2, c.Attempts) // the interruption refunded its attempt
	assert.NoError(t, s.FailChunk(ctx, c, "nmap exit 1"))
	assert.Equal(t, store.ChunkCounts{Failed: 1}, must.Value(s.CountChunks(ctx, runID)))
}

// lease leases the next chunk of runID and fails the test when there is none.
func lease(t *testing.T, s *store.Store, runID int64) store.Chunk {
	t.Helper()
	c, ok, err := s.LeaseChunk(ctx, runID)
	must.Nil(err)
	if !ok {
		t.Fatalf("no pending chunk in run %d", runID)
	}
	return c
}
