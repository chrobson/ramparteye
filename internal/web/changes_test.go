package web

import (
	"net/http"
	"testing"
	"time"

	"github.com/ctx42/testing/pkg/assert"

	"github.com/chrobson/ramparteye/internal/auth"
	"github.com/chrobson/ramparteye/internal/model"
	"github.com/chrobson/ramparteye/internal/store"
)

func changesEnv(t *testing.T) *testEnv {
	t.Helper()
	e := newEnv(t)
	fin := testNow.Add(-time.Hour)
	e.st.scans.changeRuns = []store.ChangeRun{
		{RunID: 6, PrevRunID: 5, Kind: "scan", Status: store.RunDone, FinishedAt: &fin, Applied: true, Total: 6,
			Counts: map[model.ChangeKind]int{model.ChangeNew: 1, model.ChangeGone: 1, model.ChangeChanged: 1,
				model.ChangeHostUp: 1, model.ChangeHostDown: 1, model.ChangeUnstable: 1}},
		{RunID: 5, Kind: "import", Status: store.RunDone, FinishedAt: &fin, Applied: true},
		{RunID: 4, Kind: "scan", Status: store.RunCancelled},
	}
	e.st.dash.changes = []model.Change{
		{RunID: 6, Kind: model.ChangeHostUp, Key: model.AssetKey{IP: mustAddr("10.20.9.1")}},
		{RunID: 6, Kind: model.ChangeHostDown, Key: model.AssetKey{IP: mustAddr("10.20.9.2")}},
		{RunID: 6, Kind: model.ChangeUnstable, Key: model.AssetKey{IP: mustAddr("10.20.9.3")}, Field: "flips", New: "3"},
		{RunID: 6, Kind: model.ChangeNew, Key: svcKey("10.20.9.4", 8080), New: "http Jetty"},
		{RunID: 6, Kind: model.ChangeGone, Key: svcKey("10.20.9.5", 21), Old: "ftp vsftpd"},
		{RunID: 6, Kind: model.ChangeChanged, Key: svcKey("10.20.9.6", 80), Field: "product",
			Old: "<script>alert(1)</script>", New: "nginx"},
	}
	e.st.dash.counts = map[model.HostStateKind]int{model.HostUp: 30, model.HostUnstable: 1, model.HostDown: 2}
	e.st.dash.states = []model.HostState{
		{IP: mustAddr("10.20.9.3"), State: model.HostUnstable, LastSeen: testNow.Add(-time.Hour),
			Flips: []model.Flip{{RunID: 3, Up: true}, {RunID: 4, Up: false}, {RunID: 5, Up: true}, {RunID: 6, Up: false}}},
		{IP: mustAddr("10.20.9.1"), State: model.HostUp},
	}
	return e
}

func TestChangesKindsEnglish(t *testing.T) {
	e := changesEnv(t)

	rec := e.get("/changes/6", e.login(t, auth.RoleViewer))
	body := rec.Body.String()

	assert.Equal(t, http.StatusOK, rec.Code)
	for _, label := range []string{"New", "Gone", "Changed", "Host up", "Host down", "Unstable"} {
		assert.Contain(t, ">"+label+" <", body, label)
	}
	assert.Contain(t, `Compared with run <a class="font-mono underline" href="/changes/5">#5</a>`, body)
	assert.Contain(t, `href="/assets/10.20.9.4/8080/tcp"`, body)
	assert.Contain(t, "http Jetty", body)
	assert.Contain(t, "ftp vsftpd", body)
}

func TestChangesRunEscapesScannedValues(t *testing.T) {
	e := changesEnv(t)

	body := e.get("/changes/6", e.login(t, auth.RoleViewer)).Body.String()

	assert.NotContain(t, "<script>alert", body)
	assert.Contain(t, "&lt;script&gt;alert(1)&lt;/script&gt;", body)
}

func TestChangesRunUnknown(t *testing.T) {
	e := changesEnv(t)
	c := e.login(t, auth.RoleViewer)

	assert.Equal(t, http.StatusNotFound, e.get("/changes/99", c).Code)
	assert.Equal(t, http.StatusNotFound, e.get("/changes/x", c).Code)
}

func TestChangesRunNotCompared(t *testing.T) {
	e := changesEnv(t)
	e.st.dash.changes = nil

	body := e.get("/changes/4", e.login(t, auth.RoleViewer)).Body.String()

	assert.Contain(t, "not been compared", body)
}

func TestChangesOverview(t *testing.T) {
	e := changesEnv(t)
	e.st.scans.series = []store.RunPoint{
		{RunID: 4, StartedAt: testNow.Add(-3 * time.Hour), HostsUp: 10, Services: 20},
		{RunID: 5, StartedAt: testNow.Add(-2 * time.Hour), HostsUp: 12, Services: 25,
			Counts: map[model.ChangeKind]int{model.ChangeNew: 4}},
		{RunID: 6, StartedAt: testNow.Add(-time.Hour), HostsUp: 11, Services: 24,
			Counts: map[model.ChangeKind]int{model.ChangeNew: 1, model.ChangeHostDown: 1}},
	}

	rec := e.get("/changes", e.login(t, auth.RoleViewer))
	body := rec.Body.String()

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contain(t, "<svg", body)
	assert.Count(t, 3, `class="tl-bar"`, body)
	assert.Contain(t, `href="/changes/6"`, body)
	assert.Contain(t, "Run #6", body)
	assert.Contain(t, `href="/assets?state=unstable"`, body)
	assert.Contain(t, `href="/assets/10.20.9.3"`, body)
	assert.Contain(t, "3 state changes", body)
	assert.Contain(t, "import", body)
	assert.Contain(t, "Cancelled", body)
}

func TestChangesOverviewNeedsTwoRuns(t *testing.T) {
	e := changesEnv(t)
	e.st.scans.series = []store.RunPoint{{RunID: 6, HostsUp: 1}}

	body := e.get("/changes", e.login(t, auth.RoleViewer)).Body.String()

	assert.NotContain(t, "<svg", body)
	assert.Contain(t, "at least two finished scans", body)
}

func TestBuildTimeline(t *testing.T) {
	pts := []store.RunPoint{
		{RunID: 1, HostsUp: 10, Services: 20, Counts: map[model.ChangeKind]int{model.ChangeNew: 2}},
		{RunID: 2, HostsUp: 5, Services: 10, Counts: map[model.ChangeKind]int{model.ChangeNew: 3, model.ChangeGone: 1}},
		{RunID: 3},
	}

	c := buildTimeline(pts)

	assert.Len(t, 3, c.Bars)
	assert.Equal(t, 4, c.MaxChanges)
	assert.Equal(t, 20, c.MaxAssets)
	assert.Len(t, 2, c.Bars[1].Segments)
	full := chartBottom - chartTop
	assert.Epsilon(t, full*0.5, c.Bars[0].Segments[0].H, 0.01)
	assert.Epsilon(t, chartTop, c.Bars[1].Segments[1].Y, 0.01)
	assert.Len(t, 0, c.Bars[2].Segments)
	assert.Contain(t, "no changes", c.Bars[2].Title)
	assert.True(t, c.Enough())
}

func TestBuildTimelineKeepsNewest(t *testing.T) {
	var pts []store.RunPoint
	for i := range timelineRuns + 5 {
		pts = append(pts, store.RunPoint{RunID: int64(i + 1)})
	}

	c := buildTimeline(pts)

	assert.Len(t, timelineRuns, c.Bars)
	assert.Equal(t, int64(6), c.Bars[0].RunID)
	assert.False(t, buildTimeline(nil).Enough())
}
