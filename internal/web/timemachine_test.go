package web

import (
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/ctx42/testing/pkg/assert"

	"github.com/chrobson/ramparteye/internal/model"
	"github.com/chrobson/ramparteye/internal/store"
)

const (
	hostOld     = "10.20.30.40" // seen only in run 4
	hostOldDown = "10.20.30.41" // recorded without an answer in run 4
	hostImport  = "10.20.50.5"  // only in the import run 3
)

// tmEnv is assetEnv (latest run 6) plus older runs: 4 (done, profile
// "Lab nightly" over some targets), 3 (an import), 5 (failed), 2
// (cancelled) and 7 (running).
func tmEnv(t *testing.T) (*testEnv, *http.Cookie) {
	t.Helper()
	e, c := assetEnv(t)
	fin6 := testNow.Add(-12 * time.Minute)
	fin4 := testNow.Add(-50 * time.Hour)
	fin3 := testNow.Add(-70 * time.Hour)
	cfg := int64(1)
	e.st.dash.runs = []store.RunSummary{
		{ID: 7, Kind: "scan", Status: store.RunRunning},
		{ID: 6, Kind: "scan", Status: store.RunDone, FinishedAt: &fin6, ConfigID: &cfg, ConfigName: "Lab nightly", Applied: true},
		{ID: 5, Kind: "scan", Status: store.RunFailed},
		{ID: 4, Kind: "scan", Status: store.RunDone, FinishedAt: &fin4, ConfigID: &cfg, ConfigName: "Lab nightly", Applied: true},
		{ID: 3, Kind: "import", Status: store.RunDone, FinishedAt: &fin3, Applied: true},
		{ID: 2, Kind: "scan", Status: store.RunCancelled},
	}
	e.st.scans.configs = []store.ScanConfig{{ID: 1, Name: "Lab nightly", TargetIDs: []int64{5}}}
	e.st.scans.changeRuns = []store.ChangeRun{
		{RunID: 6, PrevRunID: 4, Kind: "scan", Status: store.RunDone, Applied: true},
		{RunID: 4, PrevRunID: 1, Kind: "scan", Status: store.RunDone, Applied: true},
		{RunID: 3, PrevRunID: 1, Kind: "import", Status: store.RunDone, Applied: true},
	}
	e.st.tm = map[int64]runFixture{
		4: {
			hostObs: []model.HostObs{
				{IP: mustAddr(hostAdmin), Hostname: "old-admin.internal", Up: true},
				{IP: mustAddr(hostOld), Up: true},
				{IP: mustAddr(hostOldDown), Up: false},
			},
			services: []store.ExportService{
				{ServiceObs: model.ServiceObs{ID: 41, Key: svcKey(hostAdmin, 8080), Banner: "http", Product: "Jetty"},
					HTTP: &store.HTTPSummary{URL: "http://10.20.10.10:8080/", Status: 200},
					Detections: []model.Detection{{SignatureID: "old-panel", Name: "Old Panel",
						Category: "admin-panel", Confidence: 100}}},
				{ServiceObs: model.ServiceObs{ID: 42, Key: svcKey(hostOld, 22), Banner: "ssh", Product: "OpenSSH",
					Version: "7.4"}},
			},
			changes: []model.Change{
				{RunID: 4, PrevRunID: 1, Kind: model.ChangeNew, Key: svcKey(hostOld, 22)},
				{RunID: 4, PrevRunID: 1, Kind: model.ChangeHostDown, Key: model.AssetKey{IP: mustAddr(hostNew)}},
				{RunID: 4, PrevRunID: 1, Kind: model.ChangeUnstable, Key: model.AssetKey{IP: mustAddr(hostAdmin)}},
			},
		},
		3: {
			hostObs: []model.HostObs{{IP: mustAddr(hostImport), Up: true}},
			services: []store.ExportService{
				{ServiceObs: model.ServiceObs{ID: 31, Key: svcKey(hostImport, 443), Banner: "https"}},
			},
		},
	}
	e.st.assets.http = map[int64]model.HTTPObs{41: {ServiceID: 41, URL: "http://10.20.10.10:8080/", Status: 200,
		Title: "Old admin"}}
	return e, c
}

func TestAssetsAsOfRunShowsThatRun(t *testing.T) {
	e, c := tmEnv(t)

	rec := e.get("/assets?run=4", c)
	body := rec.Body.String()

	assert.Equal(t, http.StatusOK, rec.Code)
	for _, ip := range []string{hostAdmin, hostOld, hostOldDown, hostNew} {
		assert.Contain(t, `href="/assets/`+ip+`?run=4"`, body)
	}
	assert.NotContain(t, hostUnstable, body)
	assert.NotContain(t, `href="/assets/`+hostDown, body)
	assert.Contain(t, "old-admin.internal", body)
	assert.Contain(t, "Old Panel", body)
}

func TestAssetsAsOfRunBanner(t *testing.T) {
	e, c := tmEnv(t)

	body := e.get("/assets?run=4", c).Body.String()

	assert.Contain(t, "Inventory as of run #4", body)
	assert.Contain(t, "Lab nightly", body)
	assert.Contain(t, "2 d ago", body)
	assert.Contain(t, "2026-11-22 10:00 UTC", body)
	assert.Contain(t, `href="/assets">Back to latest</a>`, body)
	assert.Contain(t, "not today", body)
	assert.Contain(t, "covers only some targets", body)
	assert.Contain(t, `href="/changes/4"`, body)
}

func TestAssetsDefaultViewHasNoBanner(t *testing.T) {
	e, c := tmEnv(t)

	body := e.get("/assets", c).Body.String()

	assert.NotContain(t, "Inventory as of run", body)
	assert.NotContain(t, "Back to latest", body)
	assert.NotContain(t, "?run=", body)
	assert.Contain(t, `href="/assets/`+hostUnstable+`"`, body)
}

func TestAssetsRunPicker(t *testing.T) {
	e, c := tmEnv(t)

	body := e.get("/assets?run=4", c).Body.String()

	assert.Contain(t, `<select name="run"`, body)
	assert.Contain(t, `<option value="">Latest</option>`, body)
	assert.Contain(t, `<option value="4" selected>`, body)
	assert.Contain(t, `<option value="6">`, body)
	assert.Contain(t, `<option value="3">`, body)
	for _, id := range []string{"7", "5", "2"} {
		assert.NotContain(t, `<option value="`+id+`"`, body)
	}
	// In the default view nothing is selected but Latest.
	def := e.get("/assets", c).Body.String()
	assert.Contain(t, `<option value="" selected>Latest</option>`, def)
}

func TestAssetsRunPrevNext(t *testing.T) {
	e, c := tmEnv(t)

	body := e.get("/assets?run=4&quick=admin", c).Body.String()

	assert.Contain(t, `href="/assets?quick=admin&amp;run=3"`, body)
	assert.Contain(t, `href="/assets?quick=admin&amp;run=6"`, body)

	oldest := e.get("/assets?run=3", c).Body.String()
	assert.NotContain(t, "Older run", oldest)
	assert.Contain(t, "Newer run", oldest)
	newest := e.get("/assets?run=6", c).Body.String()
	assert.Contain(t, "Older run", newest)
	assert.NotContain(t, "Newer run", newest)
	assert.Contain(t, "newest finished run", newest)
}

func TestAssetsAsOfRunKeepsRunInForm(t *testing.T) {
	e, c := tmEnv(t)

	body := e.get("/assets?run=4", c).Body.String()

	assert.Contain(t, `<input type="hidden" name="run" value="4">`, body)
}

func TestAssetsAsOfRunFilters(t *testing.T) {
	e, c := tmEnv(t)
	names := func(body string) []string {
		var out []string
		for _, ip := range []string{hostAdmin, hostOld, hostOldDown, hostNew} {
			if strings.Contains(body, `href="/assets/`+ip+`?run=4"`) {
				out = append(out, ip)
			}
		}
		return out
	}
	for _, tc := range []struct {
		query string
		want  []string
	}{
		{"quick=new", []string{hostOld}},
		{"quick=admin", []string{hostAdmin}},
		{"q=openssh", []string{hostOld}},
		{"q=old-admin", []string{hostAdmin}},
		{"state=down", []string{hostOldDown, hostNew}},
		{"state=up", []string{hostAdmin, hostOld}},
		{"min=50", []string{hostAdmin}},
	} {
		t.Run(tc.query, func(t *testing.T) {
			rec := e.get("/assets?run=4&"+tc.query, c)

			assert.Equal(t, http.StatusOK, rec.Code)
			assert.Equal(t, tc.want, names(rec.Body.String()))
		})
	}
}

func TestAssetsAsOfRunHTMXPartial(t *testing.T) {
	e, c := tmEnv(t)
	req := newGet("/assets?run=4&quick=new", c)
	req.Header.Set("HX-Request", "true")

	rec := serve(e, req)
	body := rec.Body.String()

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.NotContain(t, "<html", body)
	assert.Contain(t, `href="/assets/`+hostOld+`?run=4"`, body)
	assert.NotContain(t, `href="/assets/`+hostNew, body)
}

func TestAssetsAsOfRunStateColumn(t *testing.T) {
	e, c := tmEnv(t)

	body := e.get("/assets?run=4", c).Body.String()

	assert.Contain(t, "State in run #4", body)
	assert.NotContain(t, "Last seen", body)
	assert.NotContain(t, ">unstable<", body)
	assert.NotContain(t, `<option value="inactive"`, body)
}

func TestAssetsAsOfRunScoresFromThatRun(t *testing.T) {
	e, c := tmEnv(t)

	body := e.get("/assets/"+hostOld+"/22/tcp?run=4", c).Body.String()

	assert.Contain(t, "new service in this run", body)
	admin := e.get("/assets/"+hostAdmin+"/8080/tcp?run=4", c).Body.String()
	assert.Contain(t, "unstable host", admin)
}

func TestAssetsRunParamValidated(t *testing.T) {
	e, c := tmEnv(t)
	for _, tc := range []struct {
		query string
		want  int
		text  string
	}{
		{"run=abc", 400, "Invalid run"},
		{"run=0", 400, "Invalid run"},
		{"run=-4", 400, "Invalid run"},
		{"run=4.0", 400, "Invalid run"},
		{"run=+4", 400, "Invalid run"},
		{"run=99", 404, "Run not found"},
		{"run=7", 400, "has not finished"},
		{"run=5", 400, "failed"},
		{"run=2", 400, "cancelled"},
		{"run=4&state=inactive", 400, "Invalid filter"},
		{"run=4&state=unstable", 400, "Invalid filter"},
	} {
		t.Run(tc.query, func(t *testing.T) {
			rec := e.get("/assets?"+tc.query, c)

			assert.Equal(t, tc.want, rec.Code)
			assert.Contain(t, tc.text, rec.Body.String())
			assert.NotContain(t, "abc", rec.Body.String())
		})
	}
}

func TestAssetsRunParamInvalidHTMX(t *testing.T) {
	e, c := tmEnv(t)
	req := newGet("/assets?run=5", c)
	req.Header.Set("HX-Request", "true")

	rec := serve(e, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contain(t, "alert-error", rec.Body.String())
	assert.Contain(t, "failed", rec.Body.String())
	assert.NotContain(t, "<html", rec.Body.String())
}

func TestAssetsEmptyRunParamIsLatest(t *testing.T) {
	e, c := tmEnv(t)

	rec := e.get("/assets?run=&q=", c)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.NotContain(t, "Inventory as of run", rec.Body.String())
	assert.Contain(t, `href="/assets/`+hostUnstable+`"`, rec.Body.String())
}

func TestAssetsAsOfImportRun(t *testing.T) {
	e, c := tmEnv(t)

	body := e.get("/assets?run=3", c).Body.String()

	assert.Contain(t, "Inventory as of run #3", body)
	assert.Contain(t, "import", body)
	assert.Contain(t, "only the hosts of its file", body)
	assert.Contain(t, `href="/assets/`+hostImport+`?run=3"`, body)
	assert.NotContain(t, `href="/assets/`+hostAdmin, body)
}

func TestAssetsAsOfRunExportLinks(t *testing.T) {
	e, c := tmEnv(t)
	assert.NotContain(t, "/exchange/export.csv?run=4", e.get("/assets?run=4", c).Body.String())

	analyst := e.login(t, "Analyst")
	body := e.get("/assets?run=4", analyst).Body.String()

	assert.Contain(t, `href="/exchange/export.csv?run=4"`, body)
	assert.Contain(t, `href="/exchange/export.json?run=4"`, body)
}

func TestHostPageAsOfRun(t *testing.T) {
	e, c := tmEnv(t)

	rec := e.get("/assets/"+hostAdmin+"?run=4", c)
	body := rec.Body.String()

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contain(t, "Inventory as of run #4", body)
	assert.Contain(t, "8080/tcp", body)
	assert.Contain(t, "Old Panel", body)
	assert.NotContain(t, ">80/tcp<", body)
	assert.Contain(t, `href="/assets/`+hostAdmin+`/8080/tcp?run=4"`, body)
	assert.Contain(t, `href="/assets?run=4"`, body)
	assert.Contain(t, "old-admin.internal", body)
	assert.Contain(t, "up in run #4", body)
	assert.NotContain(t, "last seen", body)
	assert.Contain(t, `href="/assets/`+hostAdmin+`">Back to latest</a>`, body)
	assert.Contain(t, `href="/assets/`+hostAdmin+`?run=3"`, body)
	assert.Contain(t, `href="/assets/`+hostAdmin+`?run=6"`, body)
}

func TestHostPageAsOfRunDownHost(t *testing.T) {
	e, c := tmEnv(t)

	rec := e.get("/assets/"+hostNew+"?run=4", c)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contain(t, "no answer in run #4", rec.Body.String())
	assert.Contain(t, "Run #4 found no open services on this host.", rec.Body.String())
}

func TestHostPageAsOfRunMarksRun(t *testing.T) {
	e, c := tmEnv(t)
	e.st.assets.history = map[model.AssetKey]store.AssetTimeline{
		{IP: mustAddr(hostAdmin)}: {
			Runs: []store.AssetRun{
				{RunID: 4, StartedAt: testNow.Add(-51 * time.Hour), Covered: true, Seen: true},
				{RunID: 6, StartedAt: testNow.Add(-time.Hour), Covered: true, Seen: true},
			},
			Changes: []model.Change{{RunID: 4, Kind: model.ChangeUnstable, Key: model.AssetKey{IP: mustAddr(hostAdmin)}}},
		},
	}

	body := e.get("/assets/"+hostAdmin+"?run=4", c).Body.String()

	assert.Equal(t, 1, strings.Count(body, "run-mark"))
	assert.Contain(t, "(this run)", body)
	assert.Equal(t, 1, strings.Count(body, "change-mark"))
	assert.NotContain(t, "run-mark", e.get("/assets/"+hostAdmin, c).Body.String())
}

func TestHostPageAsOfRunUnknownHost(t *testing.T) {
	e, c := tmEnv(t)

	rec := e.get("/assets/"+hostUnstable+"?run=4", c)
	body := rec.Body.String()

	assert.Equal(t, http.StatusNotFound, rec.Code)
	assert.Contain(t, "Not seen in run #4", body)
	assert.Contain(t, `href="/assets?run=4"`, body)
	assert.Contain(t, `href="/assets/`+hostUnstable+`"`, body)
}

func TestHostPageRunParamValidated(t *testing.T) {
	e, c := tmEnv(t)

	assert.Equal(t, http.StatusBadRequest, e.get("/assets/"+hostAdmin+"?run=x", c).Code)
	assert.Equal(t, http.StatusNotFound, e.get("/assets/"+hostAdmin+"?run=99", c).Code)
	assert.Equal(t, http.StatusBadRequest, e.get("/assets/"+hostAdmin+"?run=5", c).Code)
	assert.Equal(t, http.StatusBadRequest, e.get("/assets/"+hostAdmin+"/8080/tcp?run=7", c).Code)
}

func TestHostPageAsOfRunAnnotationReadOnly(t *testing.T) {
	e, c := tmEnv(t)
	analyst := e.login(t, "Analyst")
	e.st.dash.notes = map[model.AssetKey]store.Annotation{
		{IP: mustAddr(hostAdmin)}: {Key: model.AssetKey{IP: mustAddr(hostAdmin)}, Comment: "Owned by the lab team"},
	}

	body := e.get("/assets/"+hostAdmin+"?run=4", analyst).Body.String()

	assert.Contain(t, "Owned by the lab team", body)
	assert.NotContain(t, `name="comment"`, body)
	assert.Contain(t, "current annotation", body)
	assert.Contain(t, `href="/assets/`+hostAdmin+`#annotation"`, body)
	// A viewer gets the explanation without the edit link.
	viewer := e.get("/assets/"+hostAdmin+"?run=4", c).Body.String()
	assert.Contain(t, "current annotation", viewer)
	assert.NotContain(t, "#annotation", viewer)
}

func TestServicePageAsOfRun(t *testing.T) {
	e, c := tmEnv(t)

	rec := e.get("/assets/"+hostAdmin+"/8080/tcp?run=4", c)
	body := rec.Body.String()

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contain(t, "Inventory as of run #4", body)
	assert.Contain(t, "Jetty", body)
	assert.Contain(t, "Old Panel", body)
	assert.Contain(t, "Old admin", body) // HTTP observation of run 4's service
	assert.Contain(t, `href="/assets/`+hostAdmin+`?run=4"`, body)
	assert.Contain(t, `href="/assets?run=4"`, body)
	assert.Contain(t, `href="/assets/`+hostAdmin+`/8080/tcp">Back to latest</a>`, body)
}

func TestServicePageAsOfRunUnknownService(t *testing.T) {
	e, c := tmEnv(t)

	rec := e.get("/assets/"+hostAdmin+"/80/tcp?run=4", c)

	assert.Equal(t, http.StatusNotFound, rec.Code)
	assert.Contain(t, "Not seen in run #4", rec.Body.String())
	assert.Contain(t, `href="/assets?run=4"`, rec.Body.String())
}

func TestRunPageLinksInventoryAsOfRun(t *testing.T) {
	e, c := tmEnv(t)

	assert.Contain(t, `href="/assets?run=4">Inventory as of this run</a>`, e.get("/scans/4", c).Body.String())
	assert.NotContain(t, "Inventory as of this run", e.get("/scans/7", c).Body.String())
	assert.NotContain(t, "Inventory as of this run", e.get("/scans/5", c).Body.String())
}

func TestChangeRunPageLinksInventoryAsOfRun(t *testing.T) {
	e, c := tmEnv(t)

	assert.Contain(t, `href="/assets?run=4">Inventory as of this run</a>`, e.get("/changes/4", c).Body.String())
}

func TestAssetsRunPickerKeepsFilters(t *testing.T) {
	e, c := tmEnv(t)

	body := e.get("/assets?state=inactive&q=lab&quick=admin", c).Body.String()

	assert.Contain(t, `<input type="hidden" name="q" value="lab">`, body)
	assert.Contain(t, `<input type="hidden" name="quick" value="admin">`, body)
	assert.NotContain(t, `<input type="hidden" name="state"`, body)
	up := e.get("/assets?state=up", c).Body.String()
	assert.Contain(t, `<input type="hidden" name="state" value="up">`, up)
}

func TestAssetsRunPickerAddsOlderRun(t *testing.T) {
	e, c := tmEnv(t)
	fin := testNow.Add(-1000 * time.Hour)
	for id := int64(100); id < 100+pickerRuns; id++ {
		e.st.dash.allRuns = append(e.st.dash.allRuns, store.RunSummary{ID: id, Kind: "scan", Status: store.RunDone,
			FinishedAt: &fin})
	}

	body := e.get("/assets?run=4", c).Body.String()

	assert.Len(t, pickerRuns+1, regexp.MustCompile(`<option value="[0-9]+"`).FindAllString(body, -1))
	assert.Contain(t, `<option value="4" selected>#4 · 2026-11-22 10:00 UTC · Lab nightly</option>`, body)
}
