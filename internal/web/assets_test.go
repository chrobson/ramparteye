package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ctx42/testing/pkg/assert"

	"github.com/chrobson/ramparteye/internal/diff"
	"github.com/chrobson/ramparteye/internal/model"
	"github.com/chrobson/ramparteye/internal/store"
)

const (
	hostUnstable = "10.20.60.120"
	hostAdmin    = "10.20.10.10"
	hostNew      = "10.20.9.7"
	hostDown     = "10.20.4.12"
)

func svcKey(ip string, port uint16) model.AssetKey {
	return model.AssetKey{IP: mustAddr(ip), Port: port, Proto: "tcp"}
}

// assetEnv returns a server with four hosts, a finished run and a Viewer
// session.
func assetEnv(t *testing.T) (*testEnv, *http.Cookie) {
	t.Helper()
	e, c := dashEnv(t)
	seen := testNow.Add(-4 * time.Minute)
	e.st.dash.states = []model.HostState{
		{IP: mustAddr(hostDown), State: model.HostDown, LastSeen: testNow.Add(-72 * time.Hour)},
		{IP: mustAddr(hostNew), State: model.HostUp, LastSeen: seen},
		{IP: mustAddr(hostAdmin), State: model.HostUp, LastSeen: seen},
		{IP: mustAddr(hostUnstable), State: model.HostUnstable, LastSeen: seen,
			FirstSeen: testNow.Add(-30 * 24 * time.Hour)},
	}
	e.st.dash.hostObs = []model.HostObs{
		{IP: mustAddr(hostUnstable), Hostname: "lab-cms.internal", Up: true},
		{IP: mustAddr(hostAdmin), Up: true},
		{IP: mustAddr(hostNew), Up: true},
	}
	e.st.dash.changes = []model.Change{
		{RunID: 6, Kind: model.ChangeNew, Key: svcKey(hostNew, 21)},
	}
	e.st.dash.services = []store.ExportService{
		{ServiceObs: model.ServiceObs{ID: 11, Key: svcKey(hostUnstable, 80), Banner: "http", Product: "nginx",
			Version: "1.20"},
			Hostname: "lab-cms.internal",
			HTTP:     &store.HTTPSummary{URL: "http://10.20.60.120/", Status: 200, Title: "Lab CMS"},
			Detections: []model.Detection{{SignatureID: "wordpress", Name: "WordPress", Category: "cms",
				Confidence: 90, Evidence: map[string]string{"outdated": "5.8"}}}},
		{ServiceObs: model.ServiceObs{ID: 12, Key: svcKey(hostUnstable, 3306), Banner: "mysql", Product: "MySQL",
			Version: "8.0"},
			Hostname: "lab-cms.internal",
			Detections: []model.Detection{{SignatureID: "mysql-noauth", Name: "MySQL without auth",
				Category: "other", Confidence: 85, Evidence: map[string]string{"severity": "high"}}}},
		{ServiceObs: model.ServiceObs{ID: 13, Key: svcKey(hostAdmin, 80), Banner: "http"},
			HTTP: &store.HTTPSummary{URL: "http://10.20.10.10/", Status: 200},
			Detections: []model.Detection{{SignatureID: "phpmyadmin", Name: "phpMyAdmin",
				Category: "admin-panel", Confidence: 100}}},
		{ServiceObs: model.ServiceObs{ID: 14, Key: svcKey(hostNew, 21), Banner: "ftp", Product: "vsftpd"}},
	}
	e.st.assets.sigs = []store.SignatureRow{{ID: "mysql-noauth", Name: "MySQL without auth", Enabled: true,
		YAML: `id: mysql-noauth
name: MySQL without auth
category: other
confidence: 85
cwe: [306]
attack: [T1190]
remediation: 'Bind MySQL to localhost and require a password.'
matchers:
  - type: service
    product: 'MySQL'
`}}
	return e, c
}

func TestHostPageSections(t *testing.T) {
	e, c := assetEnv(t)

	rec := e.get("/assets/"+hostUnstable, c)
	body := rec.Body.String()

	assert.Equal(t, http.StatusOK, rec.Code)
	for _, want := range []string{"Runs", "Availability this week", "Changes of this asset", "Services",
		hostUnstable, "lab-cms.internal", "unstable", "3306/tcp", "80/tcp", "MySQL without auth"} {
		assert.Contain(t, want, body)
	}
}

func TestHostPageFindingsMeta(t *testing.T) {
	e, c := assetEnv(t)

	body := e.get("/assets/"+hostUnstable, c).Body.String()

	assert.Contain(t, "CWE-306", body)
	assert.Contain(t, "T1190", body)
	assert.Contain(t, "Bind MySQL to localhost and require a password.", body)
}

func TestHostPageRunsAndAvailability(t *testing.T) {
	e, c := assetEnv(t)
	mon := time.Date(2026, 11, 23, 9, 0, 0, 0, time.UTC)
	e.st.assets.history = map[model.AssetKey]store.AssetTimeline{
		{IP: mustAddr(hostUnstable)}: {
			Runs: []store.AssetRun{
				{RunID: 4, StartedAt: mon.Add(-24 * time.Hour), Covered: true, Seen: true},
				{RunID: 5, StartedAt: mon, Covered: true, Seen: false},
				{RunID: 6, StartedAt: mon.Add(26 * time.Hour), Covered: true, Seen: true},
				{RunID: 7, StartedAt: mon.Add(27 * time.Hour), Covered: false},
			},
			Changes: []model.Change{
				{RunID: 6, Kind: model.ChangeHostUp, Key: model.AssetKey{IP: mustAddr(hostUnstable)}},
				{RunID: 5, Kind: model.ChangeHostDown, Key: model.AssetKey{IP: mustAddr(hostUnstable)}},
			},
		},
	}

	body := e.get("/assets/"+hostUnstable, c).Body.String()

	assert.Contain(t, "Availability 2/3", body)
	assert.Contain(t, "intermittent", body)
	assert.Contain(t, "Run #5", body)
	assert.Contain(t, "not seen", body)
	assert.Contain(t, "not covered", body)
	assert.Contain(t, "host up", body)
	assert.Contain(t, "host down", body)
	assert.Contain(t, "06–12", body)
}

func TestHeatmapCells(t *testing.T) {
	e, c := assetEnv(t)
	mon := time.Date(2026, 11, 23, 9, 30, 0, 0, time.UTC) // Monday 09:xx
	e.st.assets.history = map[model.AssetKey]store.AssetTimeline{
		{IP: mustAddr(hostUnstable)}: {Runs: []store.AssetRun{
			{RunID: 5, StartedAt: mon, Covered: true, Seen: true},
			{RunID: 6, StartedAt: mon.Add(7 * 24 * time.Hour), Covered: true, Seen: false},
		}},
	}

	body := e.get("/assets/"+hostUnstable, c).Body.String()

	assert.Equal(t, 168, strings.Count(body, "data-day="))
	assert.Equal(t, 168, strings.Count(body, "data-hour="))
	assert.Contain(t, `data-day="0" data-hour="9"`, body)
	assert.Contain(t, `aria-label="Monday 09:00, seen in 1 of 2 runs"`, body)
	assert.Contain(t, `aria-label="Sunday 23:00, no runs"`, body)
	assert.NotContain(t, "background:", body)
}

func TestServiceScoreBreakdown(t *testing.T) {
	e, c := assetEnv(t)

	rec := e.get("/assets/"+hostUnstable+"/3306/tcp", c)
	body := rec.Body.String()

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contain(t, "+38", body)
	assert.Contain(t, "+20", body)
	assert.Contain(t, "+5", body) // unstable host
	assert.Contain(t, "detection MySQL without auth: High", body)
	assert.Contain(t, "database or cache reachable from the network", body)
	assert.Contain(t, `<b class="font-mono">63</b>/100`, body)
}

func TestServicePageHTTPDetails(t *testing.T) {
	e, c := assetEnv(t)
	e.st.assets.http = map[int64]model.HTTPObs{11: {
		ServiceID: 11, URL: "http://10.20.60.120/", Status: 200, Title: `<script>alert(1)</script>`,
		Headers:    map[string][]string{"Server": {"nginx/1.20"}},
		Cookies:    []model.Cookie{{Name: "sid", Secure: false, HTTPOnly: true, SameSite: "Lax"}},
		ResponseMS: 1200,
		TLS:        &model.TLSInfo{Subject: "CN=lab", Issuer: "CN=lab", SelfSigned: true},
	}}

	rec := e.get("/assets/"+hostUnstable+"/80/tcp", c)
	body := rec.Body.String()

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.NotContain(t, "<script>alert(1)", body)
	assert.Contain(t, "&lt;script&gt;alert(1)&lt;/script&gt;", body)
	assert.Contain(t, "nginx/1.20", body)
	assert.Contain(t, "1200 ms", body)
	assert.Contain(t, "self-signed", body)
	assert.Contain(t, "WordPress", body)
	assert.Contain(t, "outdated", body)
}

func TestAssetParamsValidated(t *testing.T) {
	e, c := assetEnv(t)
	for _, tc := range []struct {
		name, path string
		want       int
	}{
		{"not an ip", "/assets/not-an-ip", 404},
		{"unknown host", "/assets/10.99.99.99", 404},
		{"ip with zone", "/assets/fe80::1%25eth0", 404},
		{"port zero", "/assets/" + hostUnstable + "/0/tcp", 404},
		{"port too large", "/assets/" + hostUnstable + "/70000/tcp", 404},
		{"port signed", "/assets/" + hostUnstable + "/+80/tcp", 404},
		{"bad proto", "/assets/" + hostUnstable + "/80/icmp", 404},
		{"unknown service", "/assets/" + hostUnstable + "/8080/tcp", 404},
		{"bad vhost", "/assets/" + hostUnstable + "/80/tcp?vhost=a%20b", 404},
		{"ipv4-mapped", "/assets/::ffff:" + hostUnstable, 200},
		{"service ok", "/assets/" + hostUnstable + "/80/tcp", 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, e.get(tc.path, c).Code)
		})
	}
}

func TestAssetParamNotReflected(t *testing.T) {
	e, c := assetEnv(t)

	for _, p := range []string{"/assets/%3Cscript%3Ealert(1)%3C%2Fscript%3E",
		"/assets/" + hostUnstable + "/80/%3Cscript%3E"} {
		rec := e.get(p, c)

		assert.Equal(t, http.StatusNotFound, rec.Code)
		assert.NotContain(t, "<script>alert", rec.Body.String())
		assert.NotContain(t, "alert(1)", rec.Body.String())
	}
}

func TestAssetPagesRequireLogin(t *testing.T) {
	e, _ := assetEnv(t)

	for _, p := range []string{"/assets", "/assets/" + hostUnstable, "/assets/" + hostUnstable + "/80/tcp"} {
		assert.Equal(t, http.StatusSeeOther, e.get(p, nil).Code)
	}
}

func TestHostPageEscapesHostileHostname(t *testing.T) {
	e, c := assetEnv(t)
	e.st.dash.hostObs[0].Hostname = `<img src=x onerror=alert(1)>`
	e.st.dash.services[0].Hostname = `<img src=x onerror=alert(1)>`
	e.st.dash.services[0].Product = `<b>x</b>` + strings.Repeat("A", 500)

	body := e.get("/assets/"+hostUnstable, c).Body.String()

	assert.NotContain(t, "<img src=x", body)
	assert.NotContain(t, "<b>x</b>", body)
	assert.Contain(t, "&lt;img src=x", body)
}

func assetNames(body string) []string {
	var out []string
	for _, ip := range []string{hostUnstable, hostAdmin, hostNew, hostDown} {
		if strings.Contains(body, `href="/assets/`+ip+`"`) {
			out = append(out, ip)
		}
	}
	return out
}

func TestAssetsListSortedByScore(t *testing.T) {
	e, c := assetEnv(t)

	rec := e.get("/assets", c)
	body := rec.Body.String()

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, 4, len(assetNames(body)))
	iU, iA := strings.Index(body, `href="/assets/`+hostUnstable), strings.Index(body, `href="/assets/`+hostAdmin)
	assert.True(t, iU < iA, "higher score first")
	assert.Contain(t, "Admin panels", body)
	assert.Contain(t, "Exposed DB", body)
	assert.Contain(t, "Staging", body)
	assert.Contain(t, "IoT", body)
	assert.Contain(t, "New since last scan", body)
	assert.Contain(t, `hx-get="/assets"`, body)
}

func TestAssetsListFilters(t *testing.T) {
	e, c := assetEnv(t)
	e.st.dash.services = append(e.st.dash.services,
		store.ExportService{ServiceObs: model.ServiceObs{ID: 15, Key: svcKey(hostDown, 8080), Banner: "http"},
			Detections: []model.Detection{{SignatureID: "stg", Name: "Staging site", Category: "staging", Confidence: 80}}},
		store.ExportService{ServiceObs: model.ServiceObs{ID: 16, Key: svcKey(hostDown, 554), Banner: "rtsp"},
			Detections: []model.Detection{{SignatureID: "cam", Name: "IP camera", Category: "iot", Confidence: 80}}})
	for _, tc := range []struct {
		query string
		want  []string
	}{
		{"state=unstable", []string{hostUnstable}},
		{"state=down", []string{hostDown}},
		{"min=60", []string{hostUnstable}},
		{"q=lab-cms", []string{hostUnstable}},
		{"q=10.20.9.", []string{hostNew}},
		{"q=phpmyadmin", []string{hostAdmin}},
		{"quick=admin", []string{hostAdmin}},
		{"quick=db", []string{hostUnstable}},
		{"quick=staging", []string{hostDown}},
		{"quick=iot", []string{hostDown}},
		{"quick=new", []string{hostNew}},
		{"quick=admin&state=down", nil},
	} {
		t.Run(tc.query, func(t *testing.T) {
			rec := e.get("/assets?"+tc.query, c)

			assert.Equal(t, http.StatusOK, rec.Code)
			assert.Equal(t, len(tc.want), len(assetNames(rec.Body.String())))
			for _, ip := range tc.want {
				assert.Contain(t, `href="/assets/`+ip+`"`, rec.Body.String())
			}
		})
	}
}

func TestAssetsListInvalidFilterHTMX(t *testing.T) {
	e, c := assetEnv(t)
	req := newGet("/assets?min=999", c)
	req.Header.Set("HX-Request", "true")

	rec := serve(e, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contain(t, "Invalid filter: min must be 0-100.", rec.Body.String())
	assert.NotContain(t, "<html", rec.Body.String())
}

func TestAssetsSearchTriggersOnce(t *testing.T) {
	e, c := assetEnv(t)

	body := e.get("/assets", c).Body.String()

	assert.Equal(t, 1, strings.Count(body, `hx-trigger="keyup changed delay:300ms"`))
	assert.NotContain(t, "change, keyup", body)
}

func TestAssetsListInvalidFilters(t *testing.T) {
	e, c := assetEnv(t)
	for _, q := range []string{"state=bogus", "min=abc", "min=101", "min=-1", "quick=bogus",
		"q=" + strings.Repeat("a", 201)} {
		t.Run(q, func(t *testing.T) {
			assert.Equal(t, http.StatusBadRequest, e.get("/assets?"+q, c).Code)
		})
	}
}

func TestAssetsListEscapesFilterText(t *testing.T) {
	e, c := assetEnv(t)

	body := e.get("/assets?q="+url.QueryEscape(`"><script>alert(1)</script>`), c).Body.String()

	assert.NotContain(t, "<script>alert(1)", body)
	assert.Contain(t, "No assets match", body)
}

func TestAssetsListHTMXPartial(t *testing.T) {
	e, c := assetEnv(t)
	req := newGet("/assets?quick=admin", c)
	req.Header.Set("HX-Request", "true")
	rec := serve(e, req)

	body := rec.Body.String()

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.NotContain(t, "<html", body)
	assert.NotContain(t, "RampartEye", body)
	assert.Contain(t, `href="/assets/`+hostAdmin+`"`, body)
	assert.Contain(t, "HX-Request", rec.Header().Get("Vary"))
}

func TestAssetsListNoRun(t *testing.T) {
	e := newEnv(t)

	body := e.get("/assets", e.login(t, "Viewer")).Body.String()

	assert.Contain(t, "No assets yet", body)
}

func annotationForm(extra url.Values) url.Values {
	f := url.Values{"comment": {"Known lab box"}, "tags": {"lab, owned ,lab"}, "severity": {"Low"},
		"false_positive": {"1"}}
	for k, v := range extra {
		f[k] = v
	}
	return f
}

func TestAnnotationViewerForbidden(t *testing.T) {
	e, c := assetEnv(t)

	rec := e.post("/assets/"+hostUnstable+"/annotation", annotationForm(nil), c)

	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Equal(t, 0, len(e.st.assets.upserts))
	rec = e.post("/assets/"+hostUnstable+"/80/tcp/annotation/delete", url.Values{}, c)
	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Equal(t, 0, len(e.st.assets.deleted))
}

func TestAnnotationFormHiddenForViewer(t *testing.T) {
	e, c := assetEnv(t)
	assert.NotContain(t, `name="comment"`, e.get("/assets/"+hostUnstable, c).Body.String())

	analyst := e.login(t, "Analyst")
	assert.Contain(t, `name="comment"`, e.get("/assets/"+hostUnstable, analyst).Body.String())
}

func TestAnnotationSaveHostAndService(t *testing.T) {
	e, _ := assetEnv(t)
	c := e.login(t, "Analyst")

	rec := e.post("/assets/"+hostUnstable+"/annotation", annotationForm(nil), c)
	assert.Equal(t, http.StatusSeeOther, rec.Code)
	assert.Equal(t, "/assets/"+hostUnstable, rec.Header().Get("Location"))

	rec = e.post("/assets/"+hostUnstable+"/3306/tcp/annotation", annotationForm(nil), c)
	assert.Equal(t, http.StatusSeeOther, rec.Code)
	assert.Equal(t, "/assets/"+hostUnstable+"/3306/tcp", rec.Header().Get("Location"))

	ups := e.st.assets.upserts
	assert.Equal(t, 2, len(ups))
	assert.Equal(t, model.AssetKey{IP: mustAddr(hostUnstable)}, ups[0].Key)
	assert.Equal(t, svcKey(hostUnstable, 3306), ups[1].Key)
	assert.Equal(t, "Known lab box", ups[1].Comment)
	assert.Equal(t, []string{"lab", "owned"}, ups[1].Tags)
	assert.Equal(t, "Low", ups[1].Severity)
	assert.True(t, ups[1].FalsePositive)
	assert.NotEqual(t, int64(0), ups[1].UpdatedBy)

	body := e.get("/assets/"+hostUnstable+"/3306/tcp", c).Body.String()
	assert.Contain(t, "Known lab box", body)
	assert.Contain(t, "marked as false positive", body)
}

func TestAnnotationShownToViewer(t *testing.T) {
	e, c := assetEnv(t)
	e.st.dash.notes = map[model.AssetKey]store.Annotation{
		svcKey(hostUnstable, 3306): {Key: svcKey(hostUnstable, 3306), Comment: "<b>analyst says</b>"},
	}

	body := e.get("/assets/"+hostUnstable+"/3306/tcp", c).Body.String()

	assert.Contain(t, "&lt;b&gt;analyst says&lt;/b&gt;", body)
	assert.NotContain(t, `name="comment"`, body)
}

func TestAnnotationValidation(t *testing.T) {
	e, _ := assetEnv(t)
	c := e.login(t, "Analyst")
	for name, form := range map[string]url.Values{
		"bad severity": annotationForm(url.Values{"severity": {"Urgent"}}),
		"long comment": annotationForm(url.Values{"comment": {strings.Repeat("x", 4001)}}),
		"long tag":     annotationForm(url.Values{"tags": {strings.Repeat("t", 41)}}),
		"many tags":    annotationForm(url.Values{"tags": {manyTags(21)}}),
	} {
		t.Run(name, func(t *testing.T) {
			rec := e.post("/assets/"+hostUnstable+"/annotation", form, c)

			assert.Equal(t, http.StatusUnprocessableEntity, rec.Code)
			assert.Contain(t, "not saved", rec.Body.String())
			assert.Equal(t, 0, len(e.st.assets.upserts))
		})
	}
}

func TestAnnotationUnknownHostAndKey(t *testing.T) {
	e, _ := assetEnv(t)
	c := e.login(t, "Analyst")

	assert.Equal(t, http.StatusNotFound, e.post("/assets/10.99.99.99/annotation", annotationForm(nil), c).Code)
	assert.Equal(t, http.StatusNotFound, e.post("/assets/"+hostUnstable+"/0/tcp/annotation", annotationForm(nil), c).Code)
	assert.Equal(t, 0, len(e.st.assets.upserts))
}

func TestAnnotationDelete(t *testing.T) {
	e, _ := assetEnv(t)
	c := e.login(t, "Analyst")
	e.st.dash.notes = map[model.AssetKey]store.Annotation{
		svcKey(hostUnstable, 3306): {Key: svcKey(hostUnstable, 3306), Comment: "x"},
	}

	rec := e.post("/assets/"+hostUnstable+"/3306/tcp/annotation/delete", url.Values{}, c)

	assert.Equal(t, http.StatusSeeOther, rec.Code)
	assert.Equal(t, 1, len(e.st.assets.deleted))
	rec = e.post("/assets/"+hostUnstable+"/3306/tcp/annotation/delete", url.Values{}, c)
	assert.Equal(t, http.StatusSeeOther, rec.Code, "deleting a missing annotation is not an error")
}

func TestAnnotationVhostKey(t *testing.T) {
	e, _ := assetEnv(t)
	c := e.login(t, "Analyst")
	e.st.dash.services[0].Key.VHost = "cms.example.com"

	rec := e.post("/assets/"+hostUnstable+"/80/tcp/annotation?vhost=cms.example.com", annotationForm(nil), c)

	assert.Equal(t, http.StatusSeeOther, rec.Code)
	assert.Equal(t, "cms.example.com", e.st.assets.upserts[0].Key.VHost)
	assert.Equal(t, "/assets/"+hostUnstable+"/80/tcp?vhost=cms.example.com", rec.Header().Get("Location"))
}

func newGet(path string, c *http.Cookie) *http.Request {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if c != nil {
		req.AddCookie(c)
	}
	return req
}

func serve(e *testEnv, req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	return rec
}

func manyTags(n int) string {
	var tags []string
	for i := range n {
		tags = append(tags, "t"+strconv.Itoa(i))
	}
	return strings.Join(tags, ",")
}

func TestHeatmapPanelPerMockup(t *testing.T) {
	e, c := assetEnv(t)
	e.srv.d.Cfg.Unstable.InactiveAfterMisses = 3
	mon := time.Date(2026, 11, 23, 9, 0, 0, 0, time.UTC)
	e.st.assets.history = map[model.AssetKey]store.AssetTimeline{{IP: mustAddr(hostUnstable)}: {Runs: []store.AssetRun{
		{RunID: 1, StartedAt: mon, Covered: true, Seen: true},
		{RunID: 2, StartedAt: mon.Add(26 * time.Hour), Covered: true, Seen: false},
		{RunID: 3, StartedAt: mon.Add(27 * time.Hour), Covered: false},
		{RunID: 4, StartedAt: mon.Add(50 * time.Hour), Covered: true, Seen: false},
	}}}

	body := e.get("/assets/"+hostUnstable, c).Body.String()

	assert.Contain(t, "weekday × hour across the last 30 scans (UTC)", body)
	assert.Contain(t, "Last 30 finished scans; grey = not covered", body)
	assert.Contain(t, "Seen in runs", body)
	assert.Contain(t, `<dd class="font-mono font-semibold">1 / 3</dd>`, body)
	assert.Contain(t, "Misses in a row", body)
	assert.Contain(t, `<dd class="font-mono font-semibold">2</dd>`, body)
	assert.Contain(t, "Marked inactive after</dt><dd class=\"font-semibold\">3 misses", body)
}

func TestPlainSummary(t *testing.T) {
	week := func(weekendSeen bool) []diff.RunPresence {
		var runs []diff.RunPresence
		mon := time.Date(2026, 11, 23, 0, 0, 0, 0, time.UTC)
		for d := range 7 {
			day := mon.AddDate(0, 0, d)
			weekend := d >= 5
			runs = append(runs,
				diff.RunPresence{At: day.Add(10 * time.Hour), Covered: true, Seen: !weekend || weekendSeen},
				diff.RunPresence{At: day.Add(22 * time.Hour), Covered: true, Seen: false})
		}
		return runs
	}
	t.Run("office hours, never at weekends", func(t *testing.T) {
		a := diff.ComputeAvailability(week(false), time.UTC)

		assert.Equal(t, diff.PatternOfficeHours, a.Pattern)
		assert.Equal(t, "Up mostly 07–17 on weekdays, never at weekends.", plainSummary(a))
	})
	t.Run("office hours, weekends seen", func(t *testing.T) {
		var a diff.Availability
		a.Pattern = diff.PatternOfficeHours
		a.Week[5][3] = diff.Cell{Seen: 1, Total: 2}

		assert.Equal(t, "Up mostly 07–17 on weekdays, rarely outside those hours.", plainSummary(a))
	})
	t.Run("office hours, no weekend scans", func(t *testing.T) {
		var runs []diff.RunPresence
		mon := time.Date(2026, 11, 23, 0, 0, 0, 0, time.UTC)
		for d := range 5 {
			day := mon.AddDate(0, 0, d)
			runs = append(runs,
				diff.RunPresence{At: day.Add(10 * time.Hour), Covered: true, Seen: true},
				diff.RunPresence{At: day.Add(22 * time.Hour), Covered: true, Seen: false})
		}
		a := diff.ComputeAvailability(runs, time.UTC)

		assert.Equal(t, diff.PatternOfficeHours, a.Pattern)
		assert.Equal(t, "Up mostly 07–17 on weekdays.", plainSummary(a))
	})
	t.Run("always", func(t *testing.T) {
		a := diff.ComputeAvailability([]diff.RunPresence{{At: testNow, Covered: true, Seen: true}}, time.UTC)

		assert.Equal(t, "Seen in every scan that covered it.", plainSummary(a))
	})
	t.Run("no data", func(t *testing.T) {
		assert.Equal(t, "", plainSummary(diff.ComputeAvailability(nil, nil)))
	})
}

func TestAnnotationUnknownService(t *testing.T) {
	e, _ := assetEnv(t)
	c := e.login(t, "Analyst")

	rec := e.post("/assets/"+hostUnstable+"/8080/tcp/annotation", annotationForm(nil), c)
	assert.Equal(t, http.StatusNotFound, rec.Code)
	rec = e.post("/assets/"+hostUnstable+"/80/tcp/annotation?vhost=other.example", annotationForm(nil), c)
	assert.Equal(t, http.StatusNotFound, rec.Code, "vhost must match exactly")
	assert.Equal(t, 0, len(e.st.assets.upserts))

	// A gone service that an earlier run saw can still be annotated.
	gone := svcKey(hostUnstable, 8080)
	e.st.assets.history = map[model.AssetKey]store.AssetTimeline{gone: {Runs: []store.AssetRun{{RunID: 3, Seen: true}}}}
	rec = e.post("/assets/"+hostUnstable+"/8080/tcp/annotation", annotationForm(nil), c)
	assert.Equal(t, http.StatusSeeOther, rec.Code)
	assert.Equal(t, 1, len(e.st.assets.upserts))
}

func TestAnnotationCrossOriginRejected(t *testing.T) {
	e, _ := assetEnv(t)
	c := e.login(t, "Analyst")
	req := httptest.NewRequest(http.MethodPost, "/assets/"+hostUnstable+"/annotation",
		strings.NewReader(annotationForm(nil).Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	req.AddCookie(c)

	rec := serve(e, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Equal(t, 0, len(e.st.assets.upserts))
}
