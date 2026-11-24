//go:build integration

package safety_test

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/ctx42/testing/pkg/assert"
	"github.com/ctx42/testing/pkg/must"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/chrobson/ramparteye/internal/safety"
	"github.com/chrobson/ramparteye/internal/testdb"
)

func newRun(t *testing.T) (*pgxpool.Pool, int64) {
	t.Helper()
	pool := testdb.New(t)
	var id int64
	must.Nil(pool.QueryRow(context.Background(), `INSERT INTO scan_runs (kind, status, started_at, finished_at)
		VALUES ('scan', 'done', now(), now()) RETURNING id`).Scan(&id))
	return pool, id
}

func TestSaveLoadAccumulates(t *testing.T) {
	pool, runID := newRun(t)
	ctx := context.Background()

	_, err := safety.Load(ctx, pool, runID)
	assert.ErrorIs(t, safety.ErrNoReceipt, err)

	first := safety.Receipt{RunID: runID, NmapInvocations: 1, NmapRawReported: 1, NmapPackets: 100, NmapBusyMs: 2000,
		NmapPeakInvPPS: 50, ConfiguredMaxRate: 1000, PolicyPPS: 5000, PerWorkerRate: 500,
		ArgvSHA256: "abc", ArgvSample: []string{"-sn x"},
		HTTPGet: 3, HTTPHead: 1, HTTPPeakRPS: 4, HTTPRateLimit: 20, HTTPBurst: 5,
		TargetsChecked: 256, TimeWindow: "22:00-06:00", OutsideWindow: 1,
		PathProbeBudget: 2, PathProbes: 4, PathProbesRefused: 1, PathProbeSignatures: 2, PathProbeGateCalls: 5,
		ProbeHosts: map[string]int{"10.0.0.1": 2, "10.0.0.2": 2}}
	assert.NoError(t, safety.Save(ctx, pool, first))

	got, err := safety.Load(ctx, pool, runID)
	assert.NoError(t, err)
	assert.Equal(t, int64(100), got.NmapPackets)
	assert.Equal(t, 5000, got.PolicyPPS)
	assert.Equal(t, "22:00-06:00", got.TimeWindow)
	assert.Equal(t, int64(4), got.PathProbes)
	assert.Equal(t, 2, got.PathProbesMaxHost)
	assert.Equal(t, int64(5), got.PathProbeGateCalls)
	assert.Equal(t, 20.0, got.HTTPRateLimit)
	assert.Equal(t, []string{"-sn x"}, got.ArgvSample)

	// A resumed run adds to the same row: limits blank or looser than before
	// do not widen it, a missing window does not blank the stored one.
	second := safety.Receipt{RunID: runID, NmapPackets: 50, NmapPeakInvPPS: 80,
		ConfiguredMaxRate: 2000, PolicyPPS: 0, HTTPRateLimit: 50, HTTPBurst: 0, PathProbeBudget: 0,
		ArgvSHA256: "def", ArgvSample: []string{"-sn y"}, OutsideWindow: 1,
		PathProbes: 1, PathProbeGateCalls: 1, ProbeHosts: map[string]int{"10.0.0.1": 1}}
	assert.NoError(t, safety.Save(ctx, pool, second))

	got, err = safety.Load(ctx, pool, runID)
	assert.NoError(t, err)
	assert.Equal(t, int64(150), got.NmapPackets)
	assert.Equal(t, 80.0, got.NmapPeakInvPPS)
	assert.Equal(t, int64(5), got.PathProbes)
	assert.Equal(t, 3, got.PathProbesMaxHost) // 10.0.0.1 accumulated 2+1
	assert.Equal(t, int64(6), got.PathProbeGateCalls)
	assert.Equal(t, int64(2), got.OutsideWindow)
	assert.Equal(t, 1000, got.ConfiguredMaxRate)
	assert.Equal(t, 5000, got.PolicyPPS)
	assert.Equal(t, 2, got.PathProbeBudget)
	assert.Equal(t, 20.0, got.HTTPRateLimit)
	assert.Equal(t, 5, got.HTTPBurst)
	assert.Equal(t, "22:00-06:00", got.TimeWindow)
	assert.Equal(t, "abc", got.ArgvSHA256)
	assert.Equal(t, []string{"-sn x"}, got.ArgvSample)

	probes, err := safety.LoadProbes(ctx, pool, runID)
	assert.NoError(t, err)
	assert.Equal(t, map[netip.Addr]int{netip.MustParseAddr("10.0.0.1"): 3, netip.MustParseAddr("10.0.0.2"): 2}, probes)
}

// Two saves of one meter through Drain must not double-count.
func TestSaveDrainIsIdempotent(t *testing.T) {
	pool, runID := newRun(t)
	ctx := context.Background()
	m := safety.NewMeter()
	m.SetBudget(safety.Budget{PathProbesPerHost: 3})
	t0 := time.Unix(0, 0)
	m.AddNmap(safety.Invocation{Argv: []string{"a"}, Packets: 100, Elapsed: 2 * time.Second,
		Start: t0, End: t0.Add(2 * time.Second)})
	m.ProbeGate(netip.MustParseAddr("10.0.0.1"))

	for i := 0; i < 2; i++ {
		r := m.Drain(nil)
		r.RunID = runID
		assert.NoError(t, safety.Save(ctx, pool, r))
	}

	got, err := safety.Load(ctx, pool, runID)
	assert.NoError(t, err)
	assert.Equal(t, int64(100), got.NmapPackets)
	assert.Equal(t, 1, got.NmapInvocations)
	assert.Equal(t, int64(1), got.PathProbes)
	assert.Equal(t, 1, got.PathProbesMaxHost)
	assert.Equal(t, int64(1), got.PathProbeGateCalls)
}
