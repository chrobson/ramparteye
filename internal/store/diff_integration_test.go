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

func TestDiffBaselineAndScope(t *testing.T) {
	s, pool := newStore(t)
	prev := insertRun(t, pool, "scan", "done")
	imp := insertRun(t, pool, "import", "done")
	curr := must.Value(s.CreateRun(ctx, nil, []netip.Prefix{netip.MustParsePrefix("10.20.0.0/24")}))

	assert.Equal(t, prev, must.Value(s.PrevScanRunID(ctx, curr))) // imports never a baseline
	assert.Equal(t, int64(0), must.Value(s.PrevScanRunID(ctx, prev)))
	assert.True(t, must.Value(s.RunIsImport(ctx, imp)))
	assert.False(t, must.Value(s.RunIsImport(ctx, prev)))

	inside := insertService(t, pool, prev, "10.20.0.5", 22)
	insertService(t, pool, prev, "10.99.0.5", 22)
	assert.Len(t, 2, must.Value(s.RunServices(ctx, prev)))
	scoped := must.Value(s.RunServicesInScope(ctx, prev, curr))
	assert.Len(t, 1, scoped)
	assert.Equal(t, inside, scoped[0].ID)
	assert.Equal(t, model.AssetKey{IP: addr("10.20.0.5"), Port: 22, Proto: "tcp"}, scoped[0].Key)

	// An import covers exactly its hosts.
	must.Value(pool.Exec(ctx, `INSERT INTO host_obs (run_id, ip, up) VALUES ($1, '10.99.0.5', true)`, imp))
	scoped = must.Value(s.RunServicesInScope(ctx, prev, imp))
	assert.Len(t, 1, scoped)
	assert.Equal(t, addr("10.99.0.5"), scoped[0].Key.IP)

	hosts := must.Value(s.RunHostObs(ctx, imp))
	assert.Equal(t, []model.HostObs{{RunID: imp, IP: addr("10.99.0.5"), Up: true}}, hosts)

	assert.False(t, must.Value(s.DiffApplied(ctx, curr)))
	err := s.InTx(ctx, func(tx *store.Store) error {
		if err := tx.LockDiff(ctx); err != nil {
			return err
		}
		return tx.MarkDiffApplied(ctx, curr, prev, 3)
	})
	assert.NoError(t, err)
	assert.True(t, must.Value(s.DiffApplied(ctx, curr)))
}

func TestHostStates(t *testing.T) {
	s, _ := newStore(t)
	first := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	hs := []model.HostState{
		{IP: addr("10.20.0.1"), State: model.HostUp, Flips: []model.Flip{{RunID: 1, Up: true}}, FirstSeen: first, LastSeen: first},
		{IP: addr("10.99.0.1"), State: model.HostDown, Misses: 2},
	}
	assert.NoError(t, s.SaveHostStates(ctx, hs))
	hs[0].State, hs[0].Misses = model.HostInactive, 3
	assert.NoError(t, s.SaveHostStates(ctx, hs[:1]))

	all := must.Value(s.HostStates(ctx, ""))
	assert.Len(t, 2, all)
	assert.Equal(t, model.HostInactive, all[0].State)
	assert.Equal(t, 3, all[0].Misses)
	assert.Equal(t, hs[0].Flips, all[0].Flips)
	assert.Equal(t, first, all[0].FirstSeen.UTC())
	assert.Equal(t, []model.Flip{}, all[1].Flips)
	assert.Len(t, 1, must.Value(s.HostStates(ctx, "down")))
	assert.Equal(t, map[model.HostStateKind]int{model.HostInactive: 1, model.HostDown: 1},
		must.Value(s.HostStateCounts(ctx)))

	runID := must.Value(s.CreateRun(ctx, nil, []netip.Prefix{netip.MustParsePrefix("10.20.0.0/24")}))
	var scoped []model.HostState
	err := s.InTx(ctx, func(tx *store.Store) error {
		var err error
		scoped, err = tx.HostStatesInScope(ctx, runID)
		return err
	})
	assert.NoError(t, err)
	assert.Len(t, 1, scoped)
	assert.Equal(t, addr("10.20.0.1"), scoped[0].IP)
}

func TestChanges(t *testing.T) {
	s, pool := newStore(t)
	prev := insertRun(t, pool, "scan", "done")
	curr := insertRun(t, pool, "scan", "done")
	k := model.AssetKey{IP: addr("10.20.0.5"), Port: 443, Proto: "tcp"}
	cs := []model.Change{
		{RunID: curr, PrevRunID: prev, Kind: model.ChangeChanged, Key: k, Field: "version", Old: "1.0", New: "1.1"},
		{RunID: curr, Kind: model.ChangeHostUp, Key: model.AssetKey{IP: addr("10.20.0.6")}},
	}
	assert.NoError(t, s.InTx(ctx, func(tx *store.Store) error { return tx.InsertChanges(ctx, cs) }))
	assert.NoError(t, s.InsertChanges(ctx, nil))

	assert.Equal(t, cs, must.Value(s.Changes(ctx, curr)))
	assert.NoError(t, s.MarkDiffApplied(ctx, curr, prev, 2))

	runs := must.Value(s.ChangeRuns(ctx, 10))
	assert.Len(t, 2, runs)
	assert.Equal(t, curr, runs[0].RunID)
	assert.True(t, runs[0].Applied)
	assert.Equal(t, prev, runs[0].PrevRunID)
	assert.Equal(t, 2, runs[0].Total)
	assert.Equal(t, 1, runs[0].Counts[model.ChangeHostUp])
	one := must.Value(s.ChangeRun(ctx, curr))
	assert.Equal(t, "scan", one.Kind)
	assert.True(t, one.Applied)
	_, err := s.ChangeRun(ctx, -1)
	assert.ErrorIs(t, store.ErrRunNotFound, err)

	// Flips: new/gone changes of earlier diffed scan runs, per key.
	next := insertRun(t, pool, "scan", "done")
	must.Value(pool.Exec(ctx, `INSERT INTO changes (run_id, kind, ip, port, proto) VALUES ($1, 'gone', '10.20.0.5', 443, 'tcp')`, curr))
	flips := must.Value(s.ServiceFlips(ctx, next, []model.AssetKey{k}, 5))
	assert.Equal(t, map[model.AssetKey]int{k: 1}, flips)
	assert.Len(t, 0, must.Value(s.ServiceFlips(ctx, next, nil, 5)))
}

func TestRunHTTPMeasurements(t *testing.T) {
	s, pool := newStore(t)
	run := insertRun(t, pool, "scan", "done")
	a := insertService(t, pool, run, "10.20.0.5", 80)
	b := insertService(t, pool, run, "10.20.0.6", 80)
	assert.NoError(t, s.SaveHTTPObs(ctx, model.HTTPObs{ServiceID: a, URL: "http://a/", Status: 502, ResponseMS: 120}))
	assert.NoError(t, s.SaveHTTPObs(ctx, model.HTTPObs{ServiceID: b, URL: "http://b/"}))

	assert.Equal(t, map[int64]int{a: 502}, must.Value(s.RunHTTPStatus(ctx, run)))
	assert.Equal(t, map[int64]int{a: 120}, must.Value(s.RunLatencies(ctx, run)))
}

func TestAnnotations(t *testing.T) {
	s, _ := newStore(t)
	uid := must.Value(s.CreateUser(ctx, model.NewUser{Login: "ann", PasswordHash: "h", Role: "Analyst"}))
	k := model.AssetKey{IP: addr("10.20.0.5"), Port: 443, Proto: "tcp"}

	_, err := s.Annotation(ctx, k)
	assert.ErrorIs(t, store.ErrAnnotationNotFound, err)
	a := must.Value(s.UpsertAnnotation(ctx, store.Annotation{Key: k, Comment: "test box", Severity: "High", UpdatedBy: uid}))
	assert.Equal(t, []string{}, a.Tags)
	a = must.Value(s.UpsertAnnotation(ctx, store.Annotation{Key: k, Comment: "fp", Tags: []string{"x"}, FalsePositive: true}))
	assert.Equal(t, "", a.Severity)
	assert.Equal(t, int64(0), a.UpdatedBy)

	got := must.Value(s.Annotation(ctx, k))
	assert.Equal(t, a, got)
	host := model.AssetKey{IP: addr("10.20.0.5")}
	must.Value(s.UpsertAnnotation(ctx, store.Annotation{Key: host, Comment: "host"}))
	must.Value(s.UpsertAnnotation(ctx, store.Annotation{Key: model.AssetKey{IP: addr("10.20.0.9")}}))

	assert.Len(t, 3, must.Value(s.Annotations(ctx, netip.Addr{})))
	assert.Len(t, 2, must.Value(s.Annotations(ctx, addr("10.20.0.5"))))
	byIP := must.Value(s.AnnotationsByIPs(ctx, []netip.Addr{addr("10.20.0.5")}))
	assert.Len(t, 2, byIP)
	assert.Equal(t, "host", byIP[host].Comment)

	assert.NoError(t, s.DeleteAnnotation(ctx, k, uid))
	assert.ErrorIs(t, store.ErrAnnotationNotFound, s.DeleteAnnotation(ctx, k, uid))
	audit := must.Value(s.AuditEntries(ctx, 10))
	assert.Equal(t, "annotation.delete", audit[0].Action)
	assert.Equal(t, "ann", audit[0].Login)
	assert.Len(t, 5, audit) // four upserts and one delete
}
