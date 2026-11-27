package web

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ctx42/testing/pkg/assert"

	"github.com/chrobson/ramparteye/internal/auth"
	"github.com/chrobson/ramparteye/internal/config"
	"github.com/chrobson/ramparteye/internal/dojo"
	"github.com/chrobson/ramparteye/internal/model"
	"github.com/chrobson/ramparteye/internal/safety"
	"github.com/chrobson/ramparteye/internal/store"
)

func TestMetricsDisabledWithoutToken(t *testing.T) {
	e := newMonEnv(t, &fakeMonitor{}, withoutMetrics())

	for _, authz := range []string{"", "Bearer " + metricsToken, "Bearer "} {
		rec := e.getAuth("/metrics", authz)

		assert.Equal(t, http.StatusNotFound, rec.Code)
		assert.Equal(t, "", rec.Header().Get("WWW-Authenticate"))
		assert.Contain(t, "Page not found", rec.Body.String())
	}
	assert.Equal(t, 0, e.mon.count("ScanRunCounts"))
}

func TestMetricsDisabledPostIsNotFoundToo(t *testing.T) {
	e := newMonEnv(t, &fakeMonitor{}, withoutMetrics())

	rec := e.post("/metrics", nil, nil)

	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestMetricsRejectsMissingOrWrongToken(t *testing.T) {
	e := newMonEnv(t, &fakeMonitor{})
	tests := map[string]string{
		"none":          "",
		"empty bearer":  "Bearer ",
		"wrong":         "Bearer wrong-token-wrong-token",
		"prefix":        "Bearer " + metricsToken[:len(metricsToken)-1],
		"extra suffix":  "Bearer " + metricsToken + "x",
		"basic":         "Basic " + metricsToken,
		"no scheme":     metricsToken,
		"two spaces":    "Bearer  " + metricsToken,
		"token as user": "Bearer " + metricsToken + " extra",
	}
	for name, authz := range tests {
		t.Run(name, func(t *testing.T) {
			rec := e.getAuth("/metrics", authz)

			assert.Equal(t, http.StatusUnauthorized, rec.Code)
			assert.Equal(t, "Bearer", rec.Header().Get("WWW-Authenticate"))
			assert.Equal(t, "", rec.Body.String())
			assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
		})
	}
	assert.Equal(t, 0, e.mon.count("ScanRunCounts"))
}

func TestMetricsAcceptsTheToken(t *testing.T) {
	e := newMonEnv(t, &fakeMonitor{})

	for _, authz := range []string{"Bearer " + metricsToken, "bearer " + metricsToken, "BEARER " + metricsToken} {
		rec := e.getAuth("/metrics", authz)

		assert.Equal(t, http.StatusOK, rec.Code, authz)
	}
}

func TestMetricsResponseHeaders(t *testing.T) {
	e := newMonEnv(t, &fakeMonitor{})

	h := e.scrape().Header()

	assert.Equal(t, "text/plain; version=0.0.4; charset=utf-8", h.Get("Content-Type"))
	assert.Equal(t, "no-store", h.Get("Cache-Control"))
	assert.Equal(t, "nosniff", h.Get("X-Content-Type-Options"))
	assert.Equal(t, "DENY", h.Get("X-Frame-Options"))
	assert.Contain(t, "default-src 'self'", h.Get("Content-Security-Policy"))
	assert.NotEqual(t, "", h.Get(InstanceHeader))
}

// A session is not a credential for /metrics, and /metrics sets none.
func TestMetricsIgnoresSessions(t *testing.T) {
	e := newMonEnv(t, &fakeMonitor{})
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.AddCookie(e.login(t, auth.RoleAdmin))
	rec := httptest.NewRecorder()

	e.h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Len(t, 0, e.scrape().Result().Cookies())
}

func TestMetricsOnlyGet(t *testing.T) {
	e := newMonEnv(t, &fakeMonitor{})
	req := httptest.NewRequest(http.MethodPost, "/metrics", strings.NewReader("x"))
	req.Header.Set("Authorization", "Bearer "+metricsToken)
	rec := httptest.NewRecorder()

	e.h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

func TestMetricsNeedsAMonitor(t *testing.T) {
	_, err := NewServer(Deps{Store: newFakeStore(), Cfg: config.Config{MetricsToken: metricsToken}})

	assert.ErrorContain(t, "Monitor", err)
}

func TestMetricsBuildInfoAndEmptyDatabase(t *testing.T) {
	e := newMonEnv(t, &fakeMonitor{})

	got := e.scrape().Body.String()

	assert.Contain(t, "# HELP ramparteye_build_info ", got)
	assert.Contain(t, "# TYPE ramparteye_build_info gauge\n", got)
	assert.Contain(t, "ramparteye_build_info{version=\"v9.9.9-test\"} 1\n", got)
	// Nothing finished yet: no last-scan, latest-run, diff or receipt samples.
	for _, name := range []string{"ramparteye_last_scan_", "ramparteye_latest_run_", "ramparteye_latest_diff_",
		"ramparteye_safety_receipt_", "ramparteye_defectdojo_last_push"} {
		assert.NotContain(t, name, got)
	}
	// Zero-filled enumerations are still there.
	assert.Contain(t, "ramparteye_scan_runs{status=\"done\"} 0\n", got)
	assert.Contain(t, "ramparteye_hosts{state=\"unstable\"} 0\n", got)
	assert.Contain(t, "ramparteye_defectdojo_configured 0\n", got)
	assert.Contain(t, "ramparteye_collector_success{collector=\"runs\"} 1\n", got)
}

func fullMonitor() *fakeMonitor {
	fin := time.Date(2026, 11, 24, 3, 30, 0, 0, time.UTC)
	return &fakeMonitor{
		runCounts: map[string]int{"done": 12, "failed": 1, "cancelled": 2, "queued": 1, "running": 1},
		lastScan:  &store.FinishedScan{ID: 12, FinishedAt: fin, Duration: 452500 * time.Millisecond},
		hosts:     map[model.HostStateKind]int{model.HostUp: 31, model.HostDown: 4, model.HostUnstable: 2},
		inventory: store.RunInventory{
			RunID: 12, Services: 77,
			Detections: []store.DetectionGroup{
				{Severity: "", Category: "admin-panel", N: 2},
				{Severity: "high", Category: "cms", N: 3},
				{Severity: "Critical", Category: "server", N: 1},
				{Severity: "", Category: "server", N: 40},
				{Severity: "", Category: "cms", N: 5},
				{Severity: "urgent!", Category: "whatever", N: 6}, // not a severity: falls back to the category
			},
			DiffRunID: 12,
			Changes:   map[model.ChangeKind]int{model.ChangeNew: 5, model.ChangeGone: 1, model.ChangeChanged: 7},
		},
		receiptRun: 12,
		receipt:    okReceipt(),
	}
}

func okReceipt() safety.Receipt {
	r := receiptMixed()
	r.HTTPOther, r.UncheckedInvocations = 0, 0
	return r
}

const fullOutput = `# HELP ramparteye_build_info Build information; the value is always 1.
# TYPE ramparteye_build_info gauge
ramparteye_build_info{version="v9.9.9-test"} 1
# HELP ramparteye_scan_runs_active Scan runs executing in this process now.
# TYPE ramparteye_scan_runs_active gauge
ramparteye_scan_runs_active 2
# HELP ramparteye_scan_runs Scan runs by status.
# TYPE ramparteye_scan_runs gauge
ramparteye_scan_runs{status="queued"} 1
ramparteye_scan_runs{status="running"} 1
ramparteye_scan_runs{status="paused"} 0
ramparteye_scan_runs{status="done"} 12
ramparteye_scan_runs{status="failed"} 1
ramparteye_scan_runs{status="cancelled"} 2
# HELP ramparteye_last_scan_finished_timestamp_seconds Unix time the latest finished scan (status done) ended.
# TYPE ramparteye_last_scan_finished_timestamp_seconds gauge
ramparteye_last_scan_finished_timestamp_seconds 1795491000
# HELP ramparteye_last_scan_duration_seconds Scanning time of the latest finished scan.
# TYPE ramparteye_last_scan_duration_seconds gauge
ramparteye_last_scan_duration_seconds 452.5
# HELP ramparteye_hosts Known hosts by state.
# TYPE ramparteye_hosts gauge
ramparteye_hosts{state="up"} 31
ramparteye_hosts{state="down"} 4
ramparteye_hosts{state="inactive"} 0
ramparteye_hosts{state="unstable"} 2
# HELP ramparteye_latest_run_services Services seen in the latest finished run.
# TYPE ramparteye_latest_run_services gauge
ramparteye_latest_run_services 77
# HELP ramparteye_latest_run_detections Detections in the latest finished run by severity.
# TYPE ramparteye_latest_run_detections gauge
ramparteye_latest_run_detections{severity="info"} 51
ramparteye_latest_run_detections{severity="low"} 0
ramparteye_latest_run_detections{severity="medium"} 2
ramparteye_latest_run_detections{severity="high"} 3
ramparteye_latest_run_detections{severity="critical"} 1
# HELP ramparteye_latest_diff_changes Changes of the latest applied diff by kind.
# TYPE ramparteye_latest_diff_changes gauge
ramparteye_latest_diff_changes{kind="new"} 5
ramparteye_latest_diff_changes{kind="gone"} 1
ramparteye_latest_diff_changes{kind="changed"} 7
ramparteye_latest_diff_changes{kind="host_up"} 0
ramparteye_latest_diff_changes{kind="host_down"} 0
ramparteye_latest_diff_changes{kind="unstable"} 0
# HELP ramparteye_safety_receipt_ok 1 when every check of the safety receipt of the latest finished scan run passed, 0 when one failed or was not measured.
# TYPE ramparteye_safety_receipt_ok gauge
ramparteye_safety_receipt_ok 1
# HELP ramparteye_safety_receipt_checks Checks of that safety receipt by outcome.
# TYPE ramparteye_safety_receipt_checks gauge
ramparteye_safety_receipt_checks{status="pass"} 5
ramparteye_safety_receipt_checks{status="fail"} 0
ramparteye_safety_receipt_checks{status="unmeasured"} 0
# HELP ramparteye_defectdojo_configured 1 when a DefectDojo URL and token are configured.
# TYPE ramparteye_defectdojo_configured gauge
ramparteye_defectdojo_configured 1
# HELP ramparteye_defectdojo_last_push_ok 1 when the latest DefectDojo push attempt succeeded (skipped pushes ignored); absent before the first push.
# TYPE ramparteye_defectdojo_last_push_ok gauge
ramparteye_defectdojo_last_push_ok 0
# HELP ramparteye_defectdojo_last_push_timestamp_seconds Unix time of the latest DefectDojo push attempt.
# TYPE ramparteye_defectdojo_last_push_timestamp_seconds gauge
ramparteye_defectdojo_last_push_timestamp_seconds 1795502400
# HELP ramparteye_collector_success 1 when the queries of a metric group succeeded; 0 means the group is missing from this response.
# TYPE ramparteye_collector_success gauge
ramparteye_collector_success{collector="runs"} 1
ramparteye_collector_success{collector="hosts"} 1
ramparteye_collector_success{collector="inventory"} 1
ramparteye_collector_success{collector="safety"} 1
ramparteye_collector_success{collector="defectdojo"} 1
`

func fullEnv(t *testing.T) *monEnv {
	t.Helper()
	e := newMonEnv(t, fullMonitor())
	e.runner.active = []int64{11, 12}
	ok := false
	e.pusher.chip = dojo.ChipState{Configured: true, LastOK: &ok,
		LastAt: time.Date(2026, 11, 24, 6, 40, 0, 0, time.UTC)}
	return e
}

func TestMetricsFullOutput(t *testing.T) {
	e := fullEnv(t)

	rec := e.scrape()

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, fullOutput, rec.Body.String())
}

func TestMetricsSafetyReceiptOutcomes(t *testing.T) {
	failed := receiptMixed() // one failed check, one unmeasured
	incomplete := okReceipt()
	incomplete.UncheckedInvocations = 1
	tests := []struct {
		name string
		r    safety.Receipt
		want []string
	}{
		{"failed", failed, []string{"ramparteye_safety_receipt_ok 0\n", `{status="pass"} 3`, `{status="fail"} 1`,
			`{status="unmeasured"} 1`}},
		{"incomplete", incomplete, []string{"ramparteye_safety_receipt_ok 0\n", `{status="fail"} 0`,
			`{status="unmeasured"} 1`}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := fullMonitor()
			m.receipt = tc.r
			e := newMonEnv(t, m)

			got := e.scrape().Body.String()

			for _, w := range tc.want {
				assert.Contain(t, w, got)
			}
		})
	}
}

func TestMetricsNoReceiptYet(t *testing.T) {
	m := fullMonitor()
	m.receiptRun = 0
	e := newMonEnv(t, m)

	got := e.scrape().Body.String()

	assert.NotContain(t, "ramparteye_safety_receipt_", got)
	assert.Contain(t, `ramparteye_collector_success{collector="safety"} 1`, got)
	assert.Equal(t, 0, m.count("SafetyReceipt"))
}

func TestMetricsDefectDojoStates(t *testing.T) {
	ok := true
	tests := []struct {
		name    string
		chip    dojo.ChipState
		want    []string
		notWant []string
	}{
		{"not configured", dojo.ChipState{}, []string{"ramparteye_defectdojo_configured 0\n"},
			[]string{"last_push"}},
		{"configured, never pushed", dojo.ChipState{Configured: true},
			[]string{"ramparteye_defectdojo_configured 1\n"}, []string{"last_push"}},
		{"last push ok", dojo.ChipState{Configured: true, LastOK: &ok, LastAt: testNow},
			[]string{"ramparteye_defectdojo_last_push_ok 1\n", "ramparteye_defectdojo_last_push_timestamp_seconds 1795521600\n"}, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := newMonEnv(t, &fakeMonitor{})
			e.pusher.chip = tc.chip

			got := e.scrape().Body.String()

			for _, w := range tc.want {
				assert.Contain(t, w, got)
			}
			for _, w := range tc.notWant {
				assert.NotContain(t, w, got)
			}
		})
	}
}

func TestMetricsWithoutRunnerAndPusher(t *testing.T) {
	e := newMonEnv(t, &fakeMonitor{}, func(d *Deps) { d.Runner, d.Pusher = nil, nil })

	got := e.scrape().Body.String()

	assert.NotContain(t, "ramparteye_scan_runs_active", got)
	assert.Contain(t, "ramparteye_defectdojo_configured 0\n", got)
	assert.Contain(t, `ramparteye_collector_success{collector="defectdojo"} 1`, got)
}

func TestMetricsPartialAnswerWhenAQueryFails(t *testing.T) {
	tests := []struct {
		collector string
		fail      func(*fakeMonitor)
		missing   string
	}{
		{"runs", func(m *fakeMonitor) { m.runCountsErr = errors.New("boom") }, "ramparteye_scan_runs{"},
		{"runs", func(m *fakeMonitor) { m.lastScanErr = errors.New("boom") }, "ramparteye_last_scan_"},
		{"hosts", func(m *fakeMonitor) { m.hostsErr = errors.New("boom") }, "ramparteye_hosts{"},
		{"inventory", func(m *fakeMonitor) { m.inventoryErr = errors.New("boom") }, "ramparteye_latest_run_"},
		{"safety", func(m *fakeMonitor) { m.receiptRunEr = errors.New("boom") }, "ramparteye_safety_receipt_"},
		{"safety", func(m *fakeMonitor) { m.receiptErr = errors.New("boom") }, "ramparteye_safety_receipt_"},
	}
	for _, tc := range tests {
		t.Run(tc.collector+"/"+tc.missing, func(t *testing.T) {
			m := fullMonitor()
			tc.fail(m)
			e := newMonEnv(t, m)
			e.runner.active = []int64{11, 12}

			rec := e.scrape()
			got := rec.Body.String()

			assert.Equal(t, http.StatusOK, rec.Code)
			assert.NotContain(t, tc.missing, got)
			assert.Contain(t, `ramparteye_collector_success{collector="`+tc.collector+`"} 0`, got)
			assert.Contain(t, "ramparteye_build_info{", got)
			assert.Contain(t, "ramparteye_scan_runs_active 2", got)
			assert.Count(t, 4, "} 1\n", got[strings.Index(got, "ramparteye_collector_success{"):])
			assert.Contain(t, "boom", e.logs.String())
			assert.NotContain(t, "boom", got)
		})
	}
}

func TestMetricsDefectDojoFailureIsPartial(t *testing.T) {
	e := newMonEnv(t, &fakeMonitor{})
	e.pusher.err = errors.New("history unreadable")

	got := e.scrape().Body.String()

	assert.Contain(t, `ramparteye_collector_success{collector="defectdojo"} 0`, got)
	assert.NotContain(t, "ramparteye_defectdojo_configured", got)
}

func TestMetricsAreCached(t *testing.T) {
	m := fullMonitor()
	e := newMonEnv(t, m)

	first := e.scrape().Body.String()
	m.runCounts = map[string]int{"done": 99}
	e.advance(9 * time.Second)
	second := e.scrape().Body.String()

	assert.Equal(t, first, second)
	assert.Equal(t, 1, m.count("ScanRunCounts"))

	e.advance(2 * time.Second)
	third := e.scrape().Body.String()

	assert.NotEqual(t, first, third)
	assert.Contain(t, `ramparteye_scan_runs{status="done"} 99`, third)
	assert.Equal(t, 2, m.count("ScanRunCounts"))
}

func TestMetricsFailedAuthDoesNotTouchTheDatabaseOrCache(t *testing.T) {
	m := fullMonitor()
	e := newMonEnv(t, m)

	for range 5 {
		assert.Equal(t, http.StatusUnauthorized, e.getAuth("/metrics", "Bearer nope-nope-nope-nope").Code)
	}

	assert.Equal(t, 0, m.count("ScanRunCounts"))
}

func TestMetricsCollectionIsBounded(t *testing.T) {
	m := &fakeMonitor{block: true}
	e := newMonEnv(t, m)
	e.srv.metrics.timeout = 30 * time.Millisecond

	start := time.Now()
	rec := e.scrape()

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.True(t, time.Since(start) < 3*time.Second)
	got := rec.Body.String()
	for _, c := range []string{"runs", "hosts", "inventory", "safety"} {
		assert.Contain(t, `ramparteye_collector_success{collector="`+c+`"} 0`, got)
	}
	assert.Contain(t, "ramparteye_build_info{", got)
}

func TestMetricsDefaultTimeoutIsBelowPrometheusDefaultScrapeTimeout(t *testing.T) {
	e := newMonEnv(t, &fakeMonitor{})

	assert.Equal(t, 5*time.Second, e.srv.metrics.timeout)
	assert.Equal(t, 10*time.Second, e.srv.metrics.ttl)
}

// Values and labels come from fixed enumerations and counters, never from
// what scans observed.
func TestMetricsNeverEchoScannedContent(t *testing.T) {
	m := fullMonitor()
	m.inventory.Detections = []store.DetectionGroup{
		{Severity: `high" evil="1`, Category: "10.20.0.10 vhost.example.org", N: 1},
		{Severity: "\n# HELP injected", Category: "admin-panel", N: 1},
	}
	m.hosts = map[model.HostStateKind]int{"10.20.0.10": 5, model.HostUp: 1}
	m.runCounts = map[string]int{"weird\"status": 3, "done": 1}
	m.inventory.Changes = map[model.ChangeKind]int{"banner: Apache/2.4": 3, model.ChangeNew: 1}
	e := newMonEnv(t, m)

	got := e.scrape().Body.String()

	for _, leak := range []string{"10.20.0.10", "vhost", "evil", "injected", "weird", "Apache", "banner"} {
		assert.NotContain(t, leak, got)
	}
	assert.Contain(t, `ramparteye_hosts{state="up"} 1`, got)
	assert.Contain(t, `ramparteye_latest_run_detections{severity="medium"} 1`, got)
	assert.Contain(t, `ramparteye_latest_run_detections{severity="info"} 1`, got)
}

func TestMetricsVersionIsEscaped(t *testing.T) {
	e := newMonEnv(t, &fakeMonitor{}, func(d *Deps) { d.Version = "v1\"x\\y\nz" })

	got := e.scrape().Body.String()

	assert.Contain(t, `ramparteye_build_info{version="v1\"x\\y\nz"} 1`, got)
}

func TestMetricsEmptyVersionIsUnknown(t *testing.T) {
	e := newMonEnv(t, &fakeMonitor{}, func(d *Deps) { d.Version = "" })

	assert.Contain(t, `ramparteye_build_info{version="unknown"} 1`, e.scrape().Body.String())
}
