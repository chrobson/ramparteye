//go:build integration

package store_test

import (
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/ctx42/testing/pkg/assert"
	"github.com/ctx42/testing/pkg/must"

	"github.com/chrobson/ramparteye/internal/model"
	"github.com/chrobson/ramparteye/internal/store"
)

func TestDojoConfigSingleRow(t *testing.T) {
	s, pool := newStore(t)

	def := must.Value(s.DojoConfig(ctx))
	assert.Equal(t, "", def.URL)
	assert.Nil(t, def.TokenEnc)
	assert.Equal(t, "RampartEye", def.ProductType)
	assert.Equal(t, "Continuous discovery", def.Engagement)
	assert.True(t, def.AutoPush)
	assert.False(t, def.CloseMissing)
	assert.False(t, def.ManagedByEnv)

	_, err := pool.Exec(ctx, `INSERT INTO dojo_config (id) VALUES (false)`)
	assert.Error(t, err)
	_, err = pool.Exec(ctx, `INSERT INTO dojo_config DEFAULT VALUES`)
	assert.Error(t, err)

	in := store.DojoConfig{URL: "https://dojo.example", TokenEnc: []byte("sealed"), ProductType: "PT",
		Product: "P", Engagement: "E", AutoPush: false, CloseMissing: true, ManagedByEnv: true}
	assert.NoError(t, s.SaveDojoConfig(ctx, in))
	got := must.Value(s.DojoConfig(ctx))
	assert.NotZero(t, got.UpdatedAt)
	got.UpdatedAt = in.UpdatedAt
	assert.Equal(t, in, got)

	// A nil token keeps the stored one.
	in.TokenEnc, in.URL = nil, "https://dojo2.example"
	assert.NoError(t, s.SaveDojoConfig(ctx, in))
	got = must.Value(s.DojoConfig(ctx))
	assert.Equal(t, "https://dojo2.example", got.URL)
	assert.Equal(t, []byte("sealed"), got.TokenEnc)

	var n int
	must.Nil(pool.QueryRow(ctx, `SELECT count(*) FROM dojo_config`).Scan(&n))
	assert.Equal(t, 1, n)
}

func TestDojoConfigErrorsHideToken(t *testing.T) {
	s, _ := newStore(t)

	// A URL violating the CHECK constraint makes PostgreSQL report the
	// failing row, sealed token included (as hex), in the error detail.
	err := s.SaveDojoConfig(ctx, store.DojoConfig{URL: "ftp://x", TokenEnc: []byte("TOKENMARKER")})

	assert.Error(t, err)
	msg := errorText(err)
	assert.NotContain(t, "TOKENMARKER", msg)
	assert.NotContain(t, hex.EncodeToString([]byte("TOKENMARKER")), msg)
}

func TestDojoPushes(t *testing.T) {
	s, pool := newStore(t)
	run := insertRun(t, pool, "scan", "done")
	testID := int64(7)
	assert.NoError(t, s.RecordDojoPush(ctx, store.DojoPush{RunID: &run, Trigger: "auto", Endpoint: "reimport-scan",
		Findings: 36, Added: 2, Closed: 1, TestID: &testID, OK: true, Statistics: json.RawMessage(`{"a": 1}`)}))
	assert.NoError(t, s.RecordDojoPush(ctx, store.DojoPush{RunID: &run, Trigger: "manual", OK: false, Error: "401 Unauthorized"}))
	assert.Error(t, s.RecordDojoPush(ctx, store.DojoPush{Trigger: "bogus"}))

	pushes := must.Value(s.DojoPushes(ctx, 10))
	assert.Len(t, 2, pushes)
	assert.False(t, pushes[0].OK)
	assert.Equal(t, "401 Unauthorized", pushes[0].Error)
	assert.Equal(t, json.RawMessage(`{}`), pushes[0].Statistics)
	p := pushes[1]
	assert.Equal(t, run, *p.RunID)
	assert.Equal(t, "auto", p.Trigger)
	assert.Equal(t, 36, p.Findings)
	assert.Equal(t, 2, p.Added)
	assert.Equal(t, 1, p.Closed)
	assert.Equal(t, testID, *p.TestID)
	assert.True(t, p.OK)
	assert.NotZero(t, p.At)
	assert.Len(t, 1, must.Value(s.DojoPushes(ctx, 1)))
}

func TestDojoConfigMissingRow(t *testing.T) {
	s, pool := newStore(t)
	must.Value(pool.Exec(ctx, `DELETE FROM dojo_config`))

	_, err := s.DojoConfig(ctx)
	assert.ErrorIs(t, store.ErrNotFound, err)

	err = s.SaveDojoConfig(ctx, store.DojoConfig{URL: "https://dojo.example"})
	assert.ErrorIs(t, store.ErrNotFound, err)
}

func TestDojoRunSnapshot(t *testing.T) {
	s, pool := newStore(t)
	_, err := s.DojoRun(ctx, 0)
	assert.ErrorIs(t, store.ErrRunNotFound, err)

	cfg := must.Value(s.CreateScanConfig(ctx, store.ScanConfig{Name: "dmz", TopPorts: 100, MaxRate: 100, Workers: 1,
		PortProfile: "top"}))
	old := insertRun(t, pool, "scan", "done")
	must.Value(pool.Exec(ctx, `UPDATE scan_runs SET config_id = $1 WHERE id = $2`, cfg, old))
	run := insertRun(t, pool, "scan", "done")
	must.Value(pool.Exec(ctx, `UPDATE scan_runs SET config_id = $1 WHERE id = $2`, cfg, run))
	failed := insertRun(t, pool, "scan", "failed")
	adhoc := insertRun(t, pool, "import", "done")

	insertService(t, pool, old, "10.20.0.9", 80)
	web := insertService(t, pool, run, "10.20.0.5", 443)
	insertService(t, pool, run, "10.20.0.4", 22)
	must.Value(pool.Exec(ctx, `INSERT INTO host_obs (run_id, ip, hostname, up) VALUES ($1, '10.20.0.5', 'web', true)`, run))
	assert.NoError(t, s.SaveHTTPObs(ctx, model.HTTPObs{ServiceID: web, URL: "https://10.20.0.5/", Status: 200, Title: "Panel"}))
	assert.NoError(t, s.ReplaceDetections(ctx, web, []model.Detection{{SignatureID: "wp", Name: "WordPress",
		Category: "cms", Confidence: 90}}))
	must.Value(s.UpsertAnnotation(ctx, store.Annotation{Key: model.AssetKey{IP: addr("10.20.0.5"), Port: 443,
		Proto: "tcp"}, Comment: "prod", Tags: []string{"web"}}))
	must.Value(s.UpsertAnnotation(ctx, store.Annotation{Key: model.AssetKey{IP: addr("10.99.0.1")}, Comment: "other"}))

	snap := must.Value(s.DojoRun(ctx, run))
	assert.Equal(t, run, snap.Run.ID)
	assert.Equal(t, "dmz", snap.ProfileName)
	assert.Len(t, 2, snap.Services)
	assert.Equal(t, "web", snap.Services[1].Hostname)
	assert.Len(t, 1, snap.Services[1].Detections)
	assert.Len(t, 1, snap.Annotations) // only annotations of hosts in the run
	assert.Equal(t, "prod", snap.Annotations[0].Comment)

	latest := must.Value(s.DojoRun(ctx, 0)) // 0 = latest finished run (scans win)
	assert.Equal(t, run, latest.Run.ID)
	assert.Equal(t, "", must.Value(s.DojoRun(ctx, adhoc)).ProfileName)

	_, err = s.DojoRun(ctx, failed)
	assert.ErrorIs(t, store.ErrRunNotFound, err)
}

func TestDojoLastPush(t *testing.T) {
	s, pool := newStore(t)
	cfg := must.Value(s.CreateScanConfig(ctx, store.ScanConfig{Name: "dmz", TopPorts: 100, MaxRate: 100, Workers: 1,
		PortProfile: "top"}))
	profileRun := func() int64 {
		id := insertRun(t, pool, "scan", "done")
		must.Value(pool.Exec(ctx, `UPDATE scan_runs SET config_id = $1 WHERE id = $2`, cfg, id))
		return id
	}
	r1, r2, r3 := profileRun(), profileRun(), profileRun()
	adhoc := insertRun(t, pool, "import", "done")

	assert.Equal(t, store.DojoLastPush{}, must.Value(s.DojoLastPush(ctx, r1))) // never pushed

	assert.NoError(t, s.RecordDojoPush(ctx, store.DojoPush{RunID: &r2, Trigger: "auto", Findings: 5, OK: true}))
	assert.NoError(t, s.RecordDojoPush(ctx, store.DojoPush{RunID: &r1, Trigger: "auto", Findings: 3, OK: true})) // legacy out-of-order
	assert.NoError(t, s.RecordDojoPush(ctx, store.DojoPush{RunID: &r3, Trigger: "auto", Findings: 9, OK: false}))
	assert.NoError(t, s.RecordDojoPush(ctx, store.DojoPush{RunID: &r3, Trigger: "auto", Findings: 8, Skipped: true}))
	assert.NoError(t, s.RecordDojoPush(ctx, store.DojoPush{RunID: &adhoc, Trigger: "cli", Findings: 7, OK: true}))

	last := must.Value(s.DojoLastPush(ctx, r3))
	assert.Equal(t, r2, *last.RunID)   // newest run successfully pushed
	assert.Equal(t, 3, *last.Findings) // latest successful push
	imp := must.Value(s.DojoLastPush(ctx, adhoc))
	assert.Equal(t, adhoc, *imp.RunID)
	assert.Equal(t, 7, *imp.Findings)
}

func TestDojoPushUnknownRunAndLatest(t *testing.T) {
	s, pool := newStore(t)
	run := insertRun(t, pool, "scan", "done")
	gone := int64(999999)
	assert.Nil(t, must.Value(s.LatestDojoPush(ctx, false)))

	assert.NoError(t, s.RecordDojoPush(ctx, store.DojoPush{RunID: &gone, Trigger: "manual", Error: "run not found"}))
	assert.Nil(t, must.Value(s.DojoPushes(ctx, 1))[0].RunID) // unknown run stored as NULL

	assert.NoError(t, s.RecordDojoPush(ctx, store.DojoPush{RunID: &run, Trigger: "auto", Findings: 36, OK: true}))
	for range 60 {
		assert.NoError(t, s.RecordDojoPush(ctx, store.DojoPush{RunID: &run, Trigger: "auto", Error: "HTTP 500"}))
	}
	assert.NoError(t, s.RecordDojoPush(ctx, store.DojoPush{RunID: &run, Trigger: "auto", Skipped: true,
		Error: "skipped: newer run already pushed"}))

	last := must.Value(s.LatestDojoPush(ctx, false)) // skipped rows ignored
	assert.False(t, last.OK)
	assert.Equal(t, "HTTP 500", last.Error)
	ok := must.Value(s.LatestDojoPush(ctx, true)) // beyond the newest 50 rows
	assert.Equal(t, 36, ok.Findings)
	assert.True(t, must.Value(s.DojoPushes(ctx, 1))[0].Skipped)
}
