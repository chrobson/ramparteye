//go:build integration

package store_test

import (
	"testing"
	"time"

	"github.com/ctx42/testing/pkg/assert"
	"github.com/ctx42/testing/pkg/must"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/chrobson/ramparteye/internal/model"
	"github.com/chrobson/ramparteye/internal/safety"
	"github.com/chrobson/ramparteye/internal/store"
)

func TestPing(t *testing.T) {
	s, _ := newStore(t)

	assert.NoError(t, s.Ping(ctx))
}

func TestScanRunCounts(t *testing.T) {
	s, pool := newStore(t)
	assert.Len(t, 0, must.Value(s.ScanRunCounts(ctx)))

	insertRun(t, pool, "scan", "done")
	insertRun(t, pool, "scan", "done")
	insertRun(t, pool, "scan", "failed")
	insertRun(t, pool, "scan", "queued")
	insertRun(t, pool, "import", "done") // imports are not scans

	got := must.Value(s.ScanRunCounts(ctx))

	assert.Equal(t, map[string]int{"done": 2, "failed": 1, "queued": 1}, got)
}

func TestLastFinishedScan(t *testing.T) {
	s, pool := newStore(t)
	assert.Nil(t, must.Value(s.LastFinishedScan(ctx)))

	must.Value(pool.Exec(ctx, `INSERT INTO scan_runs (kind, status, started_at, finished_at, duration_ms)
		VALUES ('scan', 'done', '2026-11-20 10:00+00', '2026-11-20 10:05+00', 300000)`))
	var newest int64
	must.Nil(pool.QueryRow(ctx, `INSERT INTO scan_runs (kind, status, started_at, finished_at, duration_ms)
		VALUES ('scan', 'done', '2026-11-22 10:00+00', '2026-11-22 10:07:30+00', 450000) RETURNING id`).Scan(&newest))
	// Not counted: a later import and a later failed scan.
	must.Value(pool.Exec(ctx, `INSERT INTO scan_runs (kind, status, finished_at, duration_ms)
		VALUES ('import', 'done', '2026-11-25 10:00+00', 1), ('scan', 'failed', '2026-11-25 10:00+00', 1)`))

	got := must.Value(s.LastFinishedScan(ctx))

	assert.NotNil(t, got)
	assert.Equal(t, newest, got.ID)
	assert.True(t, time.Date(2026, 11, 22, 10, 7, 30, 0, time.UTC).Equal(got.FinishedAt))
	assert.Equal(t, 450*time.Second, got.Duration)
}

func TestLastFinishedScanWithoutDuration(t *testing.T) {
	s, pool := newStore(t)
	must.Value(pool.Exec(ctx, `INSERT INTO scan_runs (kind, status, finished_at) VALUES ('scan', 'done', now())`))

	got := must.Value(s.LastFinishedScan(ctx))

	assert.NotNil(t, got)
	assert.Equal(t, time.Duration(0), got.Duration)
}

func insertDetection(t *testing.T, pool *pgxpool.Pool, service int64, sig, category, evidence string) {
	t.Helper()
	must.Value(pool.Exec(ctx, `INSERT INTO detections (service_id, signature_id, name, category, confidence, evidence)
		VALUES ($1, $2, $2, $3, 90, $4::jsonb)`, service, sig, category, evidence))
}

func TestLatestRunInventoryEmpty(t *testing.T) {
	s, _ := newStore(t)

	got := must.Value(s.LatestRunInventory(ctx))

	assert.Equal(t, int64(0), got.RunID)
	assert.Equal(t, int64(0), got.DiffRunID)
	assert.Equal(t, 0, got.Services)
	assert.Len(t, 0, got.Detections)
	assert.Len(t, 0, got.Changes)
}

func TestLatestRunInventory(t *testing.T) {
	s, pool := newStore(t)
	old := insertRun(t, pool, "scan", "done")
	insertService(t, pool, old, "10.0.0.1", 22)
	run := insertRun(t, pool, "scan", "done")
	a := insertService(t, pool, run, "10.0.0.1", 22)
	b := insertService(t, pool, run, "10.0.0.1", 80)
	c := insertService(t, pool, run, "10.0.0.2", 443)
	insertDetection(t, pool, a, "nginx", "server", `{}`)
	insertDetection(t, pool, b, "wp", "cms", `{"severity": "high"}`)
	insertDetection(t, pool, b, "admin", "admin-panel", `{}`)
	insertDetection(t, pool, c, "old", "server", `{"severity": "Critical", "outdated": "1.0"}`)
	insertDetection(t, pool, c, "gone", "other", `{"severity": "high"}`)
	// A running run is not "finished".
	open := insertRun(t, pool, "scan", "running")
	insertService(t, pool, open, "10.0.0.9", 9)
	for _, r := range []int64{old, run} {
		must.Value(pool.Exec(ctx, `INSERT INTO diff_runs (run_id, changes) VALUES ($1, 3)`, r))
	}
	must.Value(pool.Exec(ctx, `INSERT INTO changes (run_id, kind, ip) VALUES
		($1, 'new', '10.0.0.1'), ($1, 'new', '10.0.0.2'), ($1, 'changed', '10.0.0.1'),
		($2, 'gone', '10.0.0.7')`, run, old))

	got := must.Value(s.LatestRunInventory(ctx))

	assert.Equal(t, run, got.RunID)
	assert.Equal(t, 3, got.Services)
	// Ordered by category, then by recorded severity.
	assert.Equal(t, []store.DetectionGroup{
		{Severity: "", Category: "admin-panel", N: 1},
		{Severity: "high", Category: "cms", N: 1},
		{Severity: "high", Category: "other", N: 1},
		{Severity: "", Category: "server", N: 1},
		{Severity: "Critical", Category: "server", N: 1},
	}, got.Detections)
	assert.Equal(t, run, got.DiffRunID)
	assert.Equal(t, map[model.ChangeKind]int{model.ChangeNew: 2, model.ChangeChanged: 1}, got.Changes)
}

func TestLatestRunInventoryGroupsDetections(t *testing.T) {
	s, pool := newStore(t)
	run := insertRun(t, pool, "scan", "done")
	for i := range 3 {
		sv := insertService(t, pool, run, "10.0.0.1", 8000+i)
		insertDetection(t, pool, sv, "wp", "cms", `{"severity": "high"}`)
	}

	got := must.Value(s.LatestRunInventory(ctx))

	assert.Equal(t, []store.DetectionGroup{{Severity: "high", Category: "cms", N: 3}}, got.Detections)
}

// The latest run is chosen like the dashboard does: a scan whose diff is
// applied wins over a newer one that is not, and an import is used only
// when no scan has finished.
func TestLatestRunInventoryPicksTheDashboardRun(t *testing.T) {
	s, pool := newStore(t)
	imp := insertRun(t, pool, "import", "done")
	assert.Equal(t, imp, must.Value(s.LatestRunInventory(ctx)).RunID)

	applied := insertRun(t, pool, "scan", "done")
	must.Value(pool.Exec(ctx, `INSERT INTO diff_runs (run_id) VALUES ($1)`, applied))
	insertRun(t, pool, "scan", "done") // newer, diff not applied yet

	got := must.Value(s.LatestRunInventory(ctx))

	assert.Equal(t, applied, got.RunID)
	assert.Equal(t, applied, got.DiffRunID)
	assert.Len(t, 0, got.Changes)
}

func TestLatestReceiptRun(t *testing.T) {
	s, pool := newStore(t)
	assert.Equal(t, int64(0), must.Value(s.LatestReceiptRun(ctx)))

	noReceipt := insertRun(t, pool, "scan", "done")
	assert.Equal(t, int64(0), must.Value(s.LatestReceiptRun(ctx)))

	withReceipt := insertRun(t, pool, "scan", "cancelled")
	assert.NoError(t, s.SaveSafetyReceipt(ctx, safety.Receipt{RunID: withReceipt, NmapPackets: 1}))
	running := insertRun(t, pool, "scan", "running")
	assert.NoError(t, s.SaveSafetyReceipt(ctx, safety.Receipt{RunID: running, NmapPackets: 1}))
	imp := insertRun(t, pool, "import", "done")
	assert.NoError(t, s.SaveSafetyReceipt(ctx, safety.Receipt{RunID: imp, NmapPackets: 1}))

	assert.Equal(t, withReceipt, must.Value(s.LatestReceiptRun(ctx)))
	assert.NotEqual(t, noReceipt, withReceipt)
}
