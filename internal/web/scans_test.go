package web

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ctx42/testing/pkg/assert"

	"github.com/chrobson/ramparteye/internal/auth"
	"github.com/chrobson/ramparteye/internal/dojo"
	"github.com/chrobson/ramparteye/internal/safety"
	"github.com/chrobson/ramparteye/internal/store"
)

func ptr[T any](v T) *T { return &v }

// scansEnv has three runs: #6 done, #5 cancelled and #4 paused by a user.
func scansEnv(t *testing.T) *testEnv {
	t.Helper()
	e := newEnv(t)
	fin := testNow.Add(-12 * time.Minute)
	start := testNow.Add(-20 * time.Minute)
	e.st.dash.runs = []store.RunSummary{
		{ID: 6, ConfigID: ptr(int64(1)), ConfigName: "Lab weekly", Kind: "scan", Status: store.RunDone,
			StartedAt: &start, FinishedAt: &fin, DurationMS: ptr(int64(480000)), ChunksTotal: 4, ChunksDone: 4,
			HostsUp: 31, Services: 77, Applied: true},
		{ID: 5, ConfigName: "Lab weekly", Kind: "scan", Status: store.RunCancelled, StartedAt: &start,
			FinishedAt: &fin, ChunksTotal: 4, ChunksDone: 1},
		{ID: 4, ConfigName: "Night", Kind: "scan", Status: store.RunPaused, Stopped: true, ChunksTotal: 2},
	}
	e.st.dash.latest = 6
	return e
}

// receiptMixed has one unmeasured check (scope), one failed check (GET/HEAD
// only) and three passing ones.
func receiptMixed() safety.Receipt {
	return safety.Receipt{RunID: 6, NmapInvocations: 4, NmapRawReported: 4, NmapPackets: 4000,
		NmapBusyMs: 10000, NmapElapsedMs: 12000, NmapPeakInvPPS: 450, ConfiguredMaxRate: 1000, PolicyPPS: 5000,
		HTTPGet: 40, HTTPHead: 3, HTTPOther: 2, TargetsChecked: 512, UncheckedInvocations: 1,
		ArgvSHA256: "abcdef0123456789", ArgvSample: []string{"-sT -p 80 10.20.0.0/24"}}
}

func TestScansListShowsRuns(t *testing.T) {
	e := scansEnv(t)

	rec := e.get("/scans", e.login(t, auth.RoleViewer))
	body := rec.Body.String()

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contain(t, `href="/scans/6"`, body)
	assert.Contain(t, "Lab weekly", body)
	assert.Contain(t, "Done", body)
	assert.Contain(t, "Cancelled", body)
	assert.Contain(t, "Paused (stopped by a user)", body)
	assert.Contain(t, "8 min", body)
}

func TestScansListEmpty(t *testing.T) {
	e := newEnv(t)

	rec := e.get("/scans", e.login(t, auth.RoleOperator))

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contain(t, "No scans yet", rec.Body.String())
	assert.Contain(t, `href="/profiles"`, rec.Body.String())
}

func TestRunPageShowsReceipt(t *testing.T) {
	e := scansEnv(t)
	e.st.scans.receipts = map[int64]safety.Receipt{6: receiptMixed()}

	rec := e.get("/scans/6", e.login(t, auth.RoleViewer))
	body := rec.Body.String()

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Count(t, 5, `data-check-status=`, body)
	assert.Count(t, 1, `data-check-status="unmeasured"`, body)
	assert.Count(t, 1, `data-check-status="fail"`, body)
	assert.Count(t, 3, `data-check-status="pass"`, body)
	for _, name := range []string{"scope respected", "rate within budget", "GET/HEAD only",
		"time window respected", "path probe budget"} {
		assert.Contain(t, name, body)
	}
	assert.Contain(t, `data-report-status="failed"`, body)
	assert.Contain(t, "A safety check failed", body)
	assert.Contain(t, "-sT -p 80 10.20.0.0/24", body)
	assert.Contain(t, `href="/runs/6/safety.json"`, body)
}

func TestRunPageReceiptIncomplete(t *testing.T) {
	e := scansEnv(t)
	r := receiptMixed()
	r.HTTPOther = 0
	e.st.scans.receipts = map[int64]safety.Receipt{6: r}

	body := e.get("/scans/6", e.login(t, auth.RoleViewer)).Body.String()

	assert.Contain(t, `data-report-status="incomplete"`, body)
	assert.Contain(t, "Incomplete", body)
	assert.Contain(t, "unmeasured", body)
}

func TestRunPageReceiptOK(t *testing.T) {
	e := scansEnv(t)
	r := receiptMixed()
	r.HTTPOther, r.UncheckedInvocations = 0, 0
	e.st.scans.receipts = map[int64]safety.Receipt{6: r}

	body := e.get("/scans/6", e.login(t, auth.RoleViewer)).Body.String()

	assert.Contain(t, `data-report-status="ok"`, body)
	assert.Contain(t, "All safety checks passed", body)
}

func TestRunPageWithoutReceipt(t *testing.T) {
	e := scansEnv(t)

	rec := e.get("/scans/5", e.login(t, auth.RoleViewer))
	body := rec.Body.String()

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contain(t, "No safety receipt", body)
	assert.Contain(t, "This run was cancelled", body)
	assert.NotContain(t, "Push to DefectDojo now", body)
}

func TestRunPagePausedByUser(t *testing.T) {
	e := scansEnv(t)

	body := e.get("/scans/4", e.login(t, auth.RoleViewer)).Body.String()

	assert.Contain(t, "Paused (stopped by a user)", body)
}

func TestRunPageNotFound(t *testing.T) {
	e := scansEnv(t)
	c := e.login(t, auth.RoleViewer)

	for _, p := range []string{"/scans/99", "/scans/abc", "/scans/0", "/scans/-1", "/runs/99/safety.json"} {
		assert.Equal(t, http.StatusNotFound, e.get(p, c).Code, p)
	}
}

func TestSafetyJSON(t *testing.T) {
	e := scansEnv(t)
	e.st.scans.receipts = map[int64]safety.Receipt{6: receiptMixed()}

	rec := e.get("/runs/6/safety.json", e.login(t, auth.RoleViewer))

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
	assert.Contain(t, `"status": "failed"`, rec.Body.String())
	assert.Contain(t, `"checks"`, rec.Body.String())
}

func TestRunPushButtonByPermission(t *testing.T) {
	e := scansEnv(t)

	assert.Contain(t, "Push to DefectDojo now", e.get("/scans/6", e.login(t, auth.RoleAnalyst)).Body.String())
	assert.NotContain(t, "Push to DefectDojo now", e.get("/scans/6", e.login(t, auth.RoleViewer)).Body.String())
}

func TestRunPushNow(t *testing.T) {
	e := scansEnv(t)
	e.withPushResult(dojo.PushRecord{RunID: 6, OK: true, Findings: 12, Added: 3, Closed: 1}, nil)

	rec := e.post("/scans/6/push", nil, e.login(t, auth.RoleAnalyst))

	assert.Equal(t, http.StatusSeeOther, rec.Code)
	assert.Equal(t, "/scans/6", rec.Header().Get("Location"))
	assert.Equal(t, []string{"6:manual"}, e.pusher.pushed)

	assert.Equal(t, "Pushed 12 findings of run #6 to DefectDojo: 3 new, 1 closed.", flashOf(t, rec))
	assert.Equal(t, "dojo.push", e.st.lastAudit().Action)
}

func TestRunPushResults(t *testing.T) {
	cases := map[string]struct {
		rec  dojo.PushRecord
		err  error
		want string
	}{
		"not configured": {err: dojo.ErrNotConfigured,
			want: "DefectDojo is not configured. An administrator can set it up in Settings."},
		"stale": {err: dojo.ErrStaleRun,
			want: "Not pushed: a newer run of this scan profile has already been pushed."},
		"failed": {rec: dojo.PushRecord{Error: "HTTP 401 <b>bad token</b>"}, err: errors.New("push failed"),
			want: "Push to DefectDojo failed: HTTP 401 <b>bad token</b>"},
		"no detail": {err: errors.New("boom"), want: "Push to DefectDojo failed: boom"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			e := scansEnv(t)
			e.withPushResult(c.rec, c.err)

			rec := e.post("/scans/6/push", nil, e.login(t, auth.RoleAnalyst))

			assert.Equal(t, http.StatusSeeOther, rec.Code)
			assert.Equal(t, c.want, flashOf(t, rec))
		})
	}
}

func TestRunPushNeedsExport(t *testing.T) {
	e := scansEnv(t)

	assert.Equal(t, http.StatusForbidden, e.post("/scans/6/push", nil, e.login(t, auth.RoleViewer)).Code)
	assert.Equal(t, 0, len(e.pusher.pushed))
}

func TestRunPushOnlyFinishedRuns(t *testing.T) {
	e := scansEnv(t)

	rec := e.post("/scans/5/push", nil, e.login(t, auth.RoleAnalyst))

	assert.Equal(t, http.StatusSeeOther, rec.Code)
	assert.Equal(t, 0, len(e.pusher.pushed))
	assert.Contain(t, "Only finished runs", flashOf(t, rec))
}

func TestRunPageEscapesReceiptNotes(t *testing.T) {
	e := scansEnv(t)
	r := receiptMixed()
	r.ArgvSample = []string{"<script>alert(1)</script>"}
	e.st.scans.receipts = map[int64]safety.Receipt{6: r}

	body := e.get("/scans/6", e.login(t, auth.RoleViewer)).Body.String()

	assert.NotContain(t, "<script>alert", body)
	assert.True(t, strings.Contains(body, "&lt;script&gt;alert(1)&lt;/script&gt;"))
}

func TestRunPushDetachedFromRequest(t *testing.T) {
	e := scansEnv(t)
	e.withPushResult(dojo.PushRecord{RunID: 6, OK: true}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // the browser went away before the push started
	req := httptest.NewRequest(http.MethodPost, "/scans/6/push", nil).WithContext(ctx)
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.AddCookie(e.login(t, auth.RoleAnalyst))

	e.h.ServeHTTP(httptest.NewRecorder(), req)

	assert.Equal(t, []string{"6:manual"}, e.pusher.pushed)
	assert.NoError(t, e.pusher.pushErrAtCall)
	left := e.pusher.pushDeadline
	assert.True(t, left > time.Minute && left <= 2*time.Minute, "timeout %s", left)
}
