//go:build integration

package store_test

import (
	"testing"

	"github.com/ctx42/testing/pkg/assert"
	"github.com/ctx42/testing/pkg/must"

	"github.com/chrobson/ramparteye/internal/model"
	"github.com/chrobson/ramparteye/internal/store"
)

func TestImportRun(t *testing.T) {
	s, _ := newStore(t)
	ip := addr("10.20.0.5")
	k := model.AssetKey{IP: ip, Port: 80, Proto: "tcp"}

	var runID int64
	err := s.InTx(ctx, func(tx *store.Store) error {
		var err error
		if runID, err = tx.BeginImportRun(ctx); err != nil {
			return err
		}
		if err := tx.ImportHost(ctx, runID, model.HostObs{IP: ip, Up: false}); err != nil {
			return err
		}
		if err := tx.ImportHost(ctx, runID, model.HostObs{IP: ip, Hostname: "web", Up: true}); err != nil {
			return err
		}
		id1, err := tx.ImportService(ctx, runID, model.ServiceObs{Key: k, Product: "nginx"})
		if err != nil {
			return err
		}
		id2, err := tx.ImportService(ctx, runID, model.ServiceObs{Key: k, Product: "apache", Version: "2.4"})
		if err != nil {
			return err
		}
		assert.Equal(t, id1, id2)
		d := model.Detection{ServiceID: id1, SignatureID: "nginx", Name: "nginx", Category: "server", Confidence: 80}
		if err := tx.ImportDetection(ctx, d); err != nil {
			return err
		}
		if err := tx.ImportDetection(ctx, d); err != nil { // duplicate ignored
			return err
		}
		return tx.FinishImportRun(ctx, runID)
	})
	assert.NoError(t, err)

	run := must.Value(s.Run(ctx, runID))
	assert.Equal(t, "import", run.Kind)
	assert.Equal(t, store.RunDone, run.Status)
	hosts := must.Value(s.RunHostObs(ctx, runID))
	assert.Equal(t, []model.HostObs{{RunID: runID, IP: ip, Hostname: "web", Up: true}}, hosts)
	svcs := must.Value(s.RunServices(ctx, runID))
	assert.Len(t, 1, svcs)
	assert.Equal(t, "nginx", svcs[0].Product) // first non-empty wins
	assert.Equal(t, "2.4", svcs[0].Version)
	assert.Len(t, 1, must.Value(s.Detections(ctx, svcs[0].ID)))
}

func TestExportQueries(t *testing.T) {
	s, pool := newStore(t)
	_, err := s.LatestExportRun(ctx)
	assert.ErrorIs(t, store.ErrRunNotFound, err)

	imp := insertRun(t, pool, "import", "done")
	assert.Equal(t, imp, must.Value(s.LatestExportRun(ctx)).ID) // import when no scan finished
	run := insertRun(t, pool, "scan", "done")
	insertRun(t, pool, "scan", "failed")
	assert.Equal(t, run, must.Value(s.LatestExportRun(ctx)).ID) // scans win
	assert.Equal(t, imp, must.Value(s.ExportRunByID(ctx, imp)).ID)
	assert.False(t, must.Value(s.ExportRunByID(ctx, run)).Date().IsZero())

	must.Value(pool.Exec(ctx, `INSERT INTO host_obs (run_id, ip, hostname, up) VALUES ($1, '10.20.0.5', 'web', true)`, run))
	web := insertService(t, pool, run, "10.20.0.5", 443)
	insertService(t, pool, run, "10.20.0.4", 22)
	assert.NoError(t, s.SaveHTTPObs(ctx, model.HTTPObs{ServiceID: web, URL: "https://10.20.0.5/", Status: 200, Title: "Panel"}))
	assert.NoError(t, s.ReplaceDetections(ctx, web, []model.Detection{{SignatureID: "wp", Name: "WordPress",
		Category: "cms", Confidence: 90, Evidence: map[string]string{"generator": "WordPress 6.5"}}}))

	svcs := must.Value(s.ExportServices(ctx, run))
	assert.Len(t, 2, svcs)
	assert.Equal(t, addr("10.20.0.4"), svcs[0].Key.IP) // ordered by ip, port
	assert.Nil(t, svcs[0].HTTP)
	w := svcs[1]
	assert.Equal(t, "web", w.Hostname)
	assert.Equal(t, &store.HTTPSummary{URL: "https://10.20.0.5/", Status: 200, Title: "Panel"}, w.HTTP)
	assert.Len(t, 1, w.Detections)
	assert.Equal(t, "WordPress 6.5", w.Detections[0].Evidence["generator"])
}
