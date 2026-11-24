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

func TestHistoryPresence(t *testing.T) {
	s, pool := newStore(t)
	day := addr("10.20.0.201")    // up only in daytime runs
	always := addr("10.20.0.202") // up in every run
	outside := addr("10.99.0.201")
	for _, a := range []string{day.String(), always.String(), outside.String()} {
		must.Value(pool.Exec(ctx, `INSERT INTO host_state (ip, state) VALUES ($1::inet, 'up')`, a))
	}

	// Six finished scan runs, alternating 10:00 and 23:00, each with a done
	// chunk covering 10.20.0.0/24.
	base := time.Now()
	var runs []int64
	for i := range 6 {
		hour := 10
		if i%2 == 1 {
			hour = 23
		}
		started := time.Date(base.Year(), base.Month(), base.Day()-10+i, hour, 0, 0, 0, time.Local)
		var id int64
		must.Nil(pool.QueryRow(ctx, `INSERT INTO scan_runs (kind, status, started_at, finished_at)
			VALUES ('scan', 'done', $1::timestamptz, $1::timestamptz + interval '5 minutes') RETURNING id`, started).Scan(&id))
		runs = append(runs, id)
		must.Value(pool.Exec(ctx, `INSERT INTO scan_chunks (run_id, cidr, status) VALUES ($1, '10.20.0.0/24', 'done')`, id))
		dayRun := hour == 10
		for _, h := range []struct {
			ip string
			up bool
		}{{day.String(), dayRun}, {always.String(), true}, {outside.String(), true}} {
			must.Value(pool.Exec(ctx, `INSERT INTO host_obs (run_id, ip, up) VALUES ($1, $2::inet, $3)`, id, h.ip, h.up))
		}
		if dayRun {
			var sid int64
			must.Nil(pool.QueryRow(ctx, `INSERT INTO services (run_id, ip, port, proto, product, version)
				VALUES ($1, $2::inet, 8787, 'tcp', 'Werkzeug', '3.0') RETURNING id`, id, day.String()).Scan(&sid))
			must.Value(pool.Exec(ctx, `INSERT INTO http_obs (service_id, url, status, title) VALUES ($1, 'http://x/', 200, 'Panel')`, sid))
		}
		insertService(t, pool, id, always.String(), 22)
	}
	// A newer import never counts.
	imp := insertRun(t, pool, "import", "done")
	must.Value(pool.Exec(ctx, `INSERT INTO host_obs (run_id, ip, up) VALUES ($1, $2::inet, true)`, imp, day.String()))

	hosts := must.Value(s.HostPresence(ctx, 6))
	byKey := map[model.AssetKey]store.AssetPresence{}
	for _, p := range hosts {
		byKey[p.Key] = p
	}
	assert.HasNoKey(t, model.AssetKey{IP: outside}, byKey)
	dp := byKey[model.AssetKey{IP: day}]
	assert.Len(t, 6, dp.Samples)
	assert.Equal(t, runs[0], dp.Samples[0].RunID)
	assert.Equal(t, runs[5], dp.Samples[5].RunID)
	for i, smp := range dp.Samples {
		assert.Equal(t, i%2 == 0, smp.Seen)
	}
	assert.Len(t, 6, byKey[model.AssetKey{IP: always}].Samples)

	svcKey := model.AssetKey{IP: day, Port: 8787, Proto: "tcp"}
	var found bool
	for _, p := range must.Value(s.ServicePresence(ctx, 6)) {
		assert.NotEqual(t, outside, p.Key.IP)
		if p.Key == svcKey {
			found = true
			assert.Len(t, 6, p.Samples)
			assert.True(t, p.Samples[0].Seen)
			assert.False(t, p.Samples[1].Seen)
		}
	}
	assert.True(t, found)

	h := must.Value(s.AssetHistory(ctx, svcKey, 6))
	assert.Len(t, 6, h.Runs)
	assert.True(t, h.Runs[0].Covered)
	assert.True(t, h.Runs[0].Seen)
	assert.False(t, h.Runs[1].Seen)
	assert.Equal(t, "Werkzeug", h.Runs[0].Product)
	assert.Equal(t, 200, h.Runs[0].HTTPStatus)
	assert.Equal(t, "Panel", h.Runs[0].HTTPTitle)
	for _, r := range must.Value(s.AssetHistory(ctx, model.AssetKey{IP: outside}, 6)).Runs {
		assert.False(t, r.Covered)
	}

	series := must.Value(s.RunSeries(ctx, 6))
	assert.Len(t, 6, series)
	assert.Equal(t, runs[0], series[0].RunID)
	assert.Equal(t, runs[5], series[5].RunID)
	assert.Equal(t, 3, series[0].HostsUp)
	assert.Equal(t, 2, series[1].HostsUp)
	assert.Equal(t, 2, series[0].Services)
	assert.Equal(t, 1, series[1].Services)
}
