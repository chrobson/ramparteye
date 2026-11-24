//go:build integration

package exchange

import (
	"context"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/ctx42/testing/pkg/assert"
	"github.com/ctx42/testing/pkg/must"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/chrobson/ramparteye/internal/diff"
	"github.com/chrobson/ramparteye/internal/model"
	"github.com/chrobson/ramparteye/internal/scope"
	"github.com/chrobson/ramparteye/internal/store"
	"github.com/chrobson/ramparteye/internal/testdb"
)

var ctx = context.Background()

var cfg = diff.Config{InactiveAfterMisses: 3, UnstableIfFlips: 2, Window: 5}

func storeObs(t *testing.T, pool *pgxpool.Pool, obs Observations, s scope.Scope) (int64, Report, error) {
	t.Helper()
	var rep Report
	var id int64
	err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		var err error
		id, err = Store(ctx, tx, obs, s, &rep)
		return err
	})
	return id, rep, err
}

func TestStoreNmapImport(t *testing.T) {
	pool := testdb.New(t)
	_, obs, err := Parse(readFile(t, "nmap_sample.xml"))
	assert.NoError(t, err)

	id, rep, err := storeObs(t, pool, obs, labScope(t))

	assert.NoError(t, err)
	assert.Equal(t, 3, rep.Hosts)
	assert.Equal(t, 4, rep.Services)
	assert.Equal(t, 0, rep.Dropped)
	st := store.New(pool)
	run := must.Value(st.Run(ctx, id))
	assert.Equal(t, "import", run.Kind)
	assert.Equal(t, store.RunDone, run.Status)
	svcs := must.Value(st.ExportServices(ctx, id))
	assert.Len(t, 4, svcs)
	assert.Equal(t, "web.lab.test", svcs[0].Hostname)
}

func TestImportDropsOutOfScope(t *testing.T) {
	pool := testdb.New(t)
	_, obs, _ := Parse(readFile(t, "nmap_sample.xml"))
	narrow := must.Value(scope.New(nil, []netip.Addr{netip.MustParseAddr("10.20.0.11")}, nil))

	id, rep, err := storeObs(t, pool, obs, narrow)

	assert.NoError(t, err)
	assert.Equal(t, 2, rep.Dropped) // 10.20.0.14 and 10.20.0.15
	assert.Equal(t, 1, rep.Hosts)
	assert.Equal(t, 2, rep.Services)
	assert.Len(t, 2, rep.Errors)
	hosts := must.Value(store.New(pool).RunHostObs(ctx, id))
	assert.Len(t, 1, hosts)
	assert.Equal(t, netip.MustParseAddr("10.20.0.11"), hosts[0].IP)
}

func TestImportDropsExcludedAndMapped(t *testing.T) {
	pool := testdb.New(t)
	s := must.Value(scope.New([]netip.Prefix{netip.MustParsePrefix("10.20.0.0/24")}, nil, []netip.Addr{netip.MustParseAddr("10.20.0.11")}))
	obs := Observations{
		Hosts: []model.HostObs{{IP: netip.MustParseAddr("10.20.0.11"), Up: true}, {IP: netip.MustParseAddr("::ffff:10.20.0.12"), Up: true},
			{IP: netip.MustParseAddr("2001:db8::1"), Up: true}},
	}

	_, rep, err := storeObs(t, pool, obs, s)

	assert.NoError(t, err)
	assert.Equal(t, 2, rep.Dropped)
	assert.Equal(t, 1, rep.Hosts)
}

func TestStoreEmptyScopeStoresNothing(t *testing.T) {
	pool := testdb.New(t)
	_, obs, _ := Parse(readFile(t, "nmap_sample.xml"))

	_, _, err := storeObs(t, pool, obs, scope.Scope{})

	assert.ErrorIs(t, scope.ErrNoScope, err)
	assert.Equal(t, 0, count(t, pool, "scan_runs"))
}

func TestStoreAllOutOfScopeStoresNothing(t *testing.T) {
	pool := testdb.New(t)
	_, obs, _ := Parse(readFile(t, "nmap_sample.xml"))
	other := must.Value(scope.New([]netip.Prefix{netip.MustParsePrefix("192.168.0.0/24")}, nil, nil))

	_, rep, err := storeObs(t, pool, obs, other)

	assert.ErrorIs(t, ErrNothingToImport, err)
	assert.Equal(t, 3, rep.Dropped)
	assert.Equal(t, 0, count(t, pool, "scan_runs"))
}

func TestStoreGenericFindingsKeepsDetections(t *testing.T) {
	pool := testdb.New(t)
	_, obs, err := Parse(readFile(t, "golden_findings.json"))
	assert.NoError(t, err)

	id, rep, err := storeObs(t, pool, obs, labScope(t))

	assert.NoError(t, err)
	assert.Equal(t, 5, rep.Services)
	assert.Equal(t, 3, rep.Detections)
	svcs := must.Value(store.New(pool).ExportServices(ctx, id))
	dets := 0
	for _, s := range svcs {
		dets += len(s.Detections)
	}
	assert.Equal(t, 3, dets)
}

func TestImportAppliesDiff(t *testing.T) {
	pool := testdb.New(t)
	st := store.New(pool)
	now := time.Now()
	first := Observations{
		Hosts:    []model.HostObs{{IP: netip.MustParseAddr("10.20.0.11"), Up: true}},
		Services: []model.ServiceObs{{Key: key("10.20.0.11", 22, "tcp"), Product: "OpenSSH"}},
	}
	// A scan run is the baseline an import is compared against.
	base := must.Value(st.CreateRun(ctx, nil, nil))
	must.Nil(st.InsertObservations(ctx, base, first.Hosts, first.Services))
	must.Value(pool.Exec(ctx, `UPDATE scan_runs SET status = 'done', started_at = now(), finished_at = now() WHERE id = $1`, base))
	must.Value(st.ApplyRun(ctx, base, cfg, now))

	rep, err := Import(ctx, pool, readFile(t, "nmap_sample.xml"), labScope(t), cfg, now.Add(time.Minute))

	assert.NoError(t, err)
	assert.Equal(t, FormatNmapXML, rep.Format)
	assert.True(t, must.Value(st.DiffApplied(ctx, rep.RunID)))
	changes := must.Value(st.Changes(ctx, rep.RunID))
	assert.True(t, len(changes) > 0) // new services of the import are compared with the baseline
	for _, c := range changes {
		assert.NotEqual(t, model.ChangeGone, c.Kind) // imports never close what they do not contain
	}
}

func TestImportRollsBackOnFailure(t *testing.T) {
	pool := testdb.New(t)

	_, err := Import(ctx, pool, readFile(t, "nmap_sample.xml"), scope.Scope{}, cfg, time.Now())
	assert.ErrorIs(t, scope.ErrNoScope, err)
	other := must.Value(scope.New([]netip.Prefix{netip.MustParsePrefix("192.168.0.0/24")}, nil, nil))
	_, err = Import(ctx, pool, readFile(t, "nmap_sample.xml"), other, cfg, time.Now())
	assert.ErrorIs(t, ErrNothingToImport, err)

	assert.Equal(t, 0, count(t, pool, "scan_runs"))
}

func TestLoadSnapshotAndRoundTrip(t *testing.T) {
	pool := testdb.New(t)
	st := store.New(pool)
	rep := must.Value(Import(ctx, pool, readFile(t, "golden_findings.json"), labScope(t), cfg, time.Now()))
	must.Value(pool.Exec(ctx, `INSERT INTO annotations (ip, port, proto, vhost, false_positive)
		VALUES ('10.20.0.14', 80, 'tcp', '', true)`))

	snap, err := LoadSnapshot(ctx, st, rep.RunID)

	assert.NoError(t, err)
	assert.Equal(t, rep.RunID, snap.RunID)
	assert.Equal(t, "import", snap.RunKind)
	assert.Len(t, 5, snap.Services)
	assert.Len(t, 1, snap.Annotations)
	for _, f := range snap.Findings() {
		assert.NotEqual(t, "rampart:sig:10.20.0.14:80:phpmyadmin", f.UniqueIDFromTool) // false positive
	}
	assert.Len(t, 5, readCSV(t, snap)[1:]) // one row per service
}

func count(t *testing.T, pool *pgxpool.Pool, table string) int {
	t.Helper()
	var n int
	must.Nil(pool.QueryRow(ctx, "SELECT count(*) FROM "+table).Scan(&n))
	return n
}

func TestStoreCapsReportErrorsAndDedupesZones(t *testing.T) {
	pool := testdb.New(t)
	obs := Observations{ErrorsTruncated: 5}
	for i := range 150 {
		obs.Errors = append(obs.Errors, fmt.Sprint("e", i))
	}
	obs.Hosts = []model.HostObs{{IP: netip.MustParseAddr("10.20.0.5"), Up: true},
		{IP: netip.MustParseAddr("fe80::1%eth0")}, {IP: netip.MustParseAddr("fe80::1%eth1")}}

	_, rep, err := storeObs(t, pool, obs, labScope(t))

	assert.NoError(t, err)
	assert.Len(t, 100, rep.Errors)
	assert.Equal(t, 56, rep.ErrorsTruncated) // 50 over + 5 + the dropped-host message
	assert.Equal(t, 1, rep.Dropped) // both zones are one address
}
