//go:build integration

package store_test

import (
	"testing"
	"time"

	"github.com/ctx42/testing/pkg/assert"
	"github.com/ctx42/testing/pkg/must"

	"github.com/chrobson/ramparteye/internal/model"
	"github.com/chrobson/ramparteye/internal/store"
)

func dur(d time.Duration) *time.Duration { return &d }

func TestScanConfigs(t *testing.T) {
	s, _ := newStore(t)
	must.Value(s.InsertTargets(ctx, []model.Target{{Kind: model.TargetCIDR, Value: "10.20.0.0/23"}}, nil))
	target := must.Value(s.Targets(ctx, ""))[0]
	every := 60
	in := store.ScanConfig{
		Name: "nightly", TargetIDs: []int64{target.ID}, TopPorts: 100, MaxRate: 500, Workers: 2,
		WindowStart: dur(22 * time.Hour), WindowEnd: dur(6*time.Hour + 30*time.Minute),
		EveryMinutes: &every, Enabled: true, PortProfile: "top", ExtraPorts: true, ExtraPortList: "8443",
	}

	id, err := s.CreateScanConfig(ctx, in)
	assert.NoError(t, err)

	got := must.Value(s.ScanConfig(ctx, id))
	in.ID = id
	assert.Equal(t, in, got)
	assert.True(t, got.HasWindow())
	_, err = s.CreateScanConfig(ctx, in)
	assert.ErrorIs(t, store.ErrScanConfigNameTaken, err)

	got.Name, got.WindowStart, got.WindowEnd, got.EveryMinutes = "manual", nil, nil, nil
	got.PortProfile, got.Ports = "list", "22,80"
	assert.NoError(t, s.UpdateScanConfig(ctx, got))
	assert.Equal(t, got, must.Value(s.ScanConfig(ctx, id)))
	assert.False(t, got.HasWindow())
	assert.Len(t, 1, must.Value(s.ScanConfigs(ctx)))

	ts := must.Value(s.ScanTargets(ctx, got.TargetIDs))
	assert.Len(t, 1, ts)
	assert.Equal(t, model.TargetCIDR, ts[0].Kind)
	assert.Len(t, 1, must.Value(s.ScanTargets(ctx, nil))) // empty = every target

	_, err = s.ScanConfig(ctx, -1)
	assert.ErrorIs(t, store.ErrScanConfigNotFound, err)
	assert.ErrorIs(t, store.ErrScanConfigNotFound, s.UpdateScanConfig(ctx, store.ScanConfig{ID: -1, Name: "x"}))
}

func TestEnsureDefaultScanConfig(t *testing.T) {
	s, _ := newStore(t)

	assert.True(t, must.Value(s.EnsureDefaultScanConfig(ctx, "All targets")))
	assert.False(t, must.Value(s.EnsureDefaultScanConfig(ctx, "All targets")))

	cfgs := must.Value(s.ScanConfigs(ctx))
	assert.Len(t, 1, cfgs)
	assert.Equal(t, "auto", cfgs[0].PortProfile)
	assert.Equal(t, 1000, cfgs[0].TopPorts)
}

func TestDeleteScanConfigKeepsFinishedRuns(t *testing.T) {
	s, pool := newStore(t)
	id := must.Value(s.CreateScanConfig(ctx, store.ScanConfig{Name: "a", TopPorts: 10, MaxRate: 10, Workers: 1}))
	runID := must.Value(s.CreateRun(ctx, &id, nil))
	assert.NoError(t, s.FinishRun(ctx, runID, store.RunDone, time.Second))

	assert.NoError(t, s.DeleteScanConfig(ctx, id))

	var cfg *int64
	must.Nil(pool.QueryRow(ctx, `SELECT config_id FROM scan_runs WHERE id = $1`, runID).Scan(&cfg))
	assert.Nil(t, cfg)
	assert.ErrorIs(t, store.ErrScanConfigNotFound, s.DeleteScanConfig(ctx, id))

	busy := must.Value(s.CreateScanConfig(ctx, store.ScanConfig{Name: "b", TopPorts: 10, MaxRate: 10, Workers: 1}))
	must.Value(s.CreateRun(ctx, &busy, nil))
	assert.ErrorIs(t, store.ErrScanConfigBusy, s.DeleteScanConfig(ctx, busy))
}
