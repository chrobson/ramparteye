//go:build integration

package safety_test

import (
	"context"
	"testing"

	"github.com/ctx42/testing/pkg/assert"
	"github.com/ctx42/testing/pkg/must"

	"github.com/chrobson/ramparteye/internal/safety"
	"github.com/chrobson/ramparteye/internal/testdb"
)

func TestSaveLoadAccumulates(t *testing.T) {
	pool := testdb.New(t)
	ctx := context.Background()
	var runID int64
	must.Nil(pool.QueryRow(ctx, `INSERT INTO scan_runs (kind, status, started_at, finished_at)
		VALUES ('scan', 'done', now(), now()) RETURNING id`).Scan(&runID))

	_, err := safety.Load(ctx, pool, runID)
	assert.ErrorIs(t, safety.ErrNoReceipt, err)

	first := safety.Receipt{RunID: runID, NmapInvocations: 1, NmapRawReported: 1, NmapPackets: 100, NmapBusyMs: 2000,
		NmapPeakInvPPS: 50, ConfiguredMaxRate: 1000, PolicyPPS: 5000, PerWorkerRate: 500,
		ArgvSHA256: "abc", ArgvSample: []string{"-sn x"},
		HTTPGet: 3, HTTPHead: 1, HTTPPeakRPS: 4, HTTPRateLimit: 20, HTTPBurst: 5,
		TargetsChecked: 256, TimeWindow: "22:00-06:00", OutsideWindow: 1,
		PathProbeBudget: 2, PathProbes: 4, PathProbesRefused: 1, PathProbesMaxHost: 2}
	assert.NoError(t, safety.Save(ctx, pool, first))

	got, err := safety.Load(ctx, pool, runID)
	assert.NoError(t, err)
	assert.Equal(t, int64(100), got.NmapPackets)
	assert.Equal(t, 5000, got.PolicyPPS)
	assert.Equal(t, "22:00-06:00", got.TimeWindow)
	assert.Equal(t, int64(4), got.PathProbes)
	assert.Equal(t, 20.0, got.HTTPRateLimit)
	assert.Equal(t, []string{"-sn x"}, got.ArgvSample)

	// A resumed run adds to the same row.
	second := first
	second.NmapPackets, second.NmapPeakInvPPS, second.PathProbes, second.PathProbesMaxHost = 50, 80, 1, 1
	second.ArgvSHA256, second.ArgvSample = "def", []string{"-sn y"}
	assert.NoError(t, safety.Save(ctx, pool, second))

	got, err = safety.Load(ctx, pool, runID)
	assert.NoError(t, err)
	assert.Equal(t, int64(150), got.NmapPackets)
	assert.Equal(t, 80.0, got.NmapPeakInvPPS)
	assert.Equal(t, int64(5), got.PathProbes)
	assert.Equal(t, 2, got.PathProbesMaxHost)
	assert.Equal(t, int64(2), got.OutsideWindow)
	assert.Equal(t, "abc", got.ArgvSHA256)
	assert.Equal(t, []string{"-sn x"}, got.ArgvSample)
}
