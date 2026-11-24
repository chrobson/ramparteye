//go:build integration

package store_test

import (
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/ctx42/testing/pkg/assert"
	"github.com/ctx42/testing/pkg/must"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/chrobson/ramparteye/internal/diff"
	"github.com/chrobson/ramparteye/internal/model"
	"github.com/chrobson/ramparteye/internal/store"
)

var applyCfg = diff.Config{InactiveAfterMisses: 3, UnstableIfFlips: 2, Window: 5}

type labRun struct {
	hosts    []string
	services []model.ServiceObs
}

// insertLabRun adds a done scan run over 10.20.0.0/18 with the given hosts
// (up) and services.
func insertLabRun(t *testing.T, s *store.Store, pool *pgxpool.Pool, r labRun) int64 {
	t.Helper()
	id := must.Value(s.CreateRun(ctx, nil, []netip.Prefix{netip.MustParsePrefix("10.20.0.0/18")}))
	var hosts []model.HostObs
	for _, h := range r.hosts {
		hosts = append(hosts, model.HostObs{IP: addr(h), Up: true})
	}
	must.Nil(s.InsertObservations(ctx, id, hosts, r.services))
	must.Value(pool.Exec(ctx, `UPDATE scan_chunks SET status = 'done' WHERE run_id = $1`, id))
	must.Value(pool.Exec(ctx, `UPDATE scan_runs SET status = 'done', started_at = now(), finished_at = now()
		WHERE id = $1`, id))
	return id
}

func labSvc(ip string, port uint16, product, version string) model.ServiceObs {
	return model.ServiceObs{Key: model.AssetKey{IP: addr(ip), Port: port, Proto: "tcp"}, Product: product, Version: version}
}

func fmtChanges(cs []model.Change) []string {
	out := []string{}
	for _, c := range cs {
		key := c.Key.IP.String()
		if c.Key.Port != 0 {
			key = fmt.Sprintf("%s:%d", key, c.Key.Port)
		}
		out = append(out, fmt.Sprintf("%s %s %s %q->%q", c.Kind, key, c.Field, c.Old, c.New))
	}
	return out
}

func TestApplyRunThreeRuns(t *testing.T) {
	s, pool := newStore(t)
	t0 := time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC)
	runs := []labRun{
		{[]string{"10.20.0.10", "10.20.24.30", "10.20.60.120"}, []model.ServiceObs{
			labSvc("10.20.0.10", 80, "nginx", "1.27.3"),
			labSvc("10.20.24.30", 23, "BusyBox telnetd", ""),
			labSvc("10.20.24.30", 22, "OpenSSH", "7.4"),
			labSvc("10.20.60.120", 80, "busybox httpd", ""),
		}},
		{[]string{"10.20.0.10", "10.20.24.30"}, []model.ServiceObs{
			labSvc("10.20.0.10", 80, "nginx", "1.27.3"),
			labSvc("10.20.0.10", 8080, "Werkzeug httpd", "3.0.1"),
			labSvc("10.20.24.30", 22, "OpenSSH", "8.9p1"),
		}},
		{[]string{"10.20.0.10", "10.20.24.30", "10.20.60.120"}, []model.ServiceObs{
			labSvc("10.20.0.10", 80, "nginx", "1.27.3"),
			labSvc("10.20.0.10", 8080, "Werkzeug httpd", "3.0.1"),
			labSvc("10.20.24.30", 22, "OpenSSH", "8.9p1"),
			labSvc("10.20.60.120", 80, "busybox httpd", ""),
		}},
	}
	want := [][]string{
		{},
		{
			`new 10.20.0.10:8080  ""->"Werkzeug httpd 3.0.1"`,
			`changed 10.20.24.30:22 version "7.4"->"8.9p1"`,
			`gone 10.20.24.30:23  "BusyBox telnetd"->""`,
			`host_down 10.20.60.120  "up"->"down"`,
			`gone 10.20.60.120:80  "busybox httpd"->""`,
		},
		{
			`host_up 10.20.60.120  ""->"up"`,
			`unstable 10.20.60.120 flips ""->"2"`,
			`new 10.20.60.120:80  ""->"busybox httpd"`,
		},
	}
	var ids []int64
	for i, r := range runs {
		id := insertLabRun(t, s, pool, r)
		ids = append(ids, id)
		res, err := s.ApplyRun(ctx, id, applyCfg, t0.Add(time.Duration(i)*time.Hour))
		assert.NoError(t, err)
		stored := must.Value(s.Changes(ctx, id))
		diff.SortChanges(stored)
		assert.Equal(t, want[i], fmtChanges(stored))
		assert.Equal(t, len(stored), len(res.Changes))
		for _, c := range stored {
			assert.Equal(t, id, c.RunID)
			if i > 0 {
				assert.Equal(t, ids[i-1], c.PrevRunID)
			}
		}
		assert.True(t, must.Value(s.DiffApplied(ctx, id)))
	}

	_, err := s.ApplyRun(ctx, ids[2], applyCfg, t0)
	assert.ErrorIs(t, store.ErrAlreadyApplied, err)

	states := map[string]model.HostStateKind{}
	for _, h := range must.Value(s.HostStates(ctx, "")) {
		states[h.IP.String()] = h.State
	}
	assert.Equal(t, map[string]model.HostStateKind{
		"10.20.0.10": model.HostUp, "10.20.24.30": model.HostUp, "10.20.60.120": model.HostUnstable,
	}, states)
}

// The latency and gateway rules of a scan run read the stored HTTP
// measurements of both runs.
func TestApplyRunLatency(t *testing.T) {
	s, pool := newStore(t)
	t0 := time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC)
	r := labRun{[]string{"10.20.0.10"}, []model.ServiceObs{labSvc("10.20.0.10", 80, "nginx", "1.27.3")}}
	var ids []int64
	for i, ms := range []int{100, 900} {
		id := insertLabRun(t, s, pool, r)
		svcs := must.Value(s.RunServices(ctx, id))
		must.Nil(s.SaveHTTPObs(ctx, model.HTTPObs{ServiceID: svcs[0].ID, URL: "http://10.20.0.10/", Status: 200, ResponseMS: ms}))
		must.Value(s.ApplyRun(ctx, id, applyCfg, t0.Add(time.Duration(i)*time.Hour)))
		ids = append(ids, id)
	}
	assert.Equal(t, []string{`changed 10.20.0.10:80 response_ms "100 ms"->"900 ms"`},
		fmtChanges(must.Value(s.Changes(ctx, ids[1]))))
}
