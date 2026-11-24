package web

import (
	"bufio"
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ctx42/testing/pkg/assert"

	"github.com/chrobson/ramparteye/internal/model"
	"github.com/chrobson/ramparteye/internal/runner"
	"github.com/chrobson/ramparteye/internal/store"
)

func TestHeadline(t *testing.T) {
	t.Run("changes", func(t *testing.T) {
		d := DashboardData{HasRuns: true, NewServices: 3, HostsGone: 1, Changed: 2}

		title, sub := Headline(d)

		assert.Equal(t, "Since the last scan: 3 new exposures, 1 host gone, 2 services changed.", title)
		assert.Equal(t, "Nothing needs urgent attention.", sub)
	})
	t.Run("zero parts are left out and singular is used", func(t *testing.T) {
		title, _ := Headline(DashboardData{HasRuns: true, NewServices: 1, Changed: 1})

		assert.Equal(t, "Since the last scan: 1 new exposure, 1 service changed.", title)
	})
	t.Run("no changes", func(t *testing.T) {
		title, _ := Headline(DashboardData{HasRuns: true})

		assert.Equal(t, "No changes since the last scan.", title)
	})
	t.Run("urgent services and last scan", func(t *testing.T) {
		d := DashboardData{HasRuns: true, Urgent: 2, LastScan: "Scan #6 finished 12 min ago."}

		_, sub := Headline(d)

		assert.Equal(t, "2 services need attention first. Scan #6 finished 12 min ago.", sub)
	})
	t.Run("zero urgent keeps last scan", func(t *testing.T) {
		_, sub := Headline(DashboardData{HasRuns: true, LastScan: "Scan #6 finished 12 min ago."})

		assert.Equal(t, "Nothing needs urgent attention. Scan #6 finished 12 min ago.", sub)
	})
}

func TestHeadlineNoRuns(t *testing.T) {
	title, sub := Headline(DashboardData{})

	assert.Equal(t, "No scans yet.", title)
	assert.NotEqual(t, "", sub)

	e := newEnv(t)
	body := e.get("/", e.login(t, "Viewer")).Body.String()
	assert.Contain(t, "No scans yet.", body)
	assert.Contain(t, `href="/scans"`, body)
}

func dashEnv(t *testing.T) (*testEnv, *http.Cookie) {
	t.Helper()
	e := newEnv(t)
	fin := testNow.Add(-12 * time.Minute)
	key := func(ip string, port uint16) model.AssetKey {
		return model.AssetKey{IP: mustAddr(ip), Port: port, Proto: "tcp"}
	}
	e.st.dash = dashData{
		targets: []model.Target{{Kind: model.TargetCIDR, Value: "10.20.0.0/18"}, {Kind: model.TargetIP, Value: "10.20.9.9"}},
		runs:    []store.RunSummary{{ID: 6, Status: store.RunDone, FinishedAt: &fin}},
		latest:  6,
		changes: []model.Change{
			{RunID: 6, Kind: model.ChangeNew, Key: key("10.20.9.7", 21)},
			{RunID: 6, Kind: model.ChangeNew, Key: key("10.20.9.8", 22)},
			{RunID: 6, Kind: model.ChangeHostDown, Key: model.AssetKey{IP: mustAddr("10.20.60.120")}},
			{RunID: 6, Kind: model.ChangeChanged, Key: key("10.20.4.12", 80), Field: "version", Old: "1.20", New: "1.24"},
		},
		hostObs: []model.HostObs{{IP: mustAddr("10.20.9.7"), Up: true}, {IP: mustAddr("10.20.9.8"), Up: false}},
		services: []store.ExportService{
			{ServiceObs: model.ServiceObs{Key: key("10.20.60.120", 3306), Banner: "mysql", Product: "MySQL"}},
			{ServiceObs: model.ServiceObs{Key: key("10.20.10.10", 80), Banner: "http"},
				HTTP: &store.HTTPSummary{URL: "http://10.20.10.10/", Status: 200},
				Detections: []model.Detection{{SignatureID: "phpmyadmin", Name: "phpMyAdmin",
					Category: "admin-panel", Confidence: 100}}},
		},
		counts: map[model.HostStateKind]int{model.HostUp: 30, model.HostUnstable: 4},
	}
	return e, e.login(t, "Viewer")
}

func TestDashboardRenders(t *testing.T) {
	e, c := dashEnv(t)

	rec := e.get("/", c)
	body := rec.Body.String()

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contain(t, "Since the last scan: 2 new exposures, 1 host gone, 1 service changed.", body)
	assert.Contain(t, "Scan #6 finished 12 min ago.", body)
	assert.Contain(t, "phpMyAdmin", body)
	assert.Contain(t, "10.20.10.10:80", body)
	assert.Contain(t, "10.20.9.7:21", body)
	assert.Contain(t, "version: 1.20 → 1.24", body)
	assert.Contain(t, "<svg", body)
	assert.Contain(t, `sse-connect="/events"`, body)
	assert.Contain(t, "No scan is running.", body)
	assert.NotContain(t, "<script>", strings.ReplaceAll(body, "<script src=", ""))
}

func TestDashboardChartLabelsEscaped(t *testing.T) {
	e, c := dashEnv(t)
	e.st.dash.services[1].Detections[0].Category = `</text><script>alert(1)</script>`

	body := e.get("/", c).Body.String()

	assert.NotContain(t, "<script>alert(1)", body)
	assert.Contain(t, "&lt;/text&gt;", body)
}

func TestDashboardRequiresLogin(t *testing.T) {
	e := newEnv(t)

	rec := e.get("/", nil)

	assert.Equal(t, http.StatusSeeOther, rec.Code)
	assert.Equal(t, http.StatusSeeOther, e.get("/events", nil).Code)
}

func TestDashboardLiveSeed(t *testing.T) {
	e, c := dashEnv(t)
	e.runner.active = []int64{7}
	e.st.dash.runs = append(e.st.dash.runs, store.RunSummary{ID: 7, ConfigName: `Lab "/18"`, Status: store.RunRunning,
		ChunksTotal: 10, ChunksDone: 5})

	body := e.get("/", c).Body.String()

	assert.Contain(t, "Scan #7 in progress", body)
	assert.Contain(t, "45%", body)
	assert.Contain(t, "Lab &#34;/18&#34;", body)
}

func TestCancelAllEndpointRequiresPerm(t *testing.T) {
	t.Run("viewer is forbidden", func(t *testing.T) {
		e := newEnv(t)

		rec := e.post("/scans/cancel-all", nil, e.login(t, "Viewer"))

		assert.Equal(t, http.StatusForbidden, rec.Code)
		assert.False(t, e.runner.cancelled)
	})
	t.Run("anonymous is sent to login", func(t *testing.T) {
		e := newEnv(t)

		rec := e.post("/scans/cancel-all", nil, nil)

		assert.NotEqual(t, http.StatusOK, rec.Code)
		assert.False(t, e.runner.cancelled)
	})
	t.Run("operator cancels and sees a flash", func(t *testing.T) {
		e := newEnv(t)
		e.runner.active = []int64{3, 4}
		c := e.login(t, "Operator")

		rec := e.post("/scans/cancel-all", url.Values{}, c)

		assert.Equal(t, http.StatusSeeOther, rec.Code)
		assert.Equal(t, "/", rec.Header().Get("Location"))
		assert.True(t, e.runner.cancelled)
		assert.Equal(t, e.st.user(1).ID, e.runner.cancelBy)

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.AddCookie(c)
		for _, fc := range rec.Result().Cookies() {
			req.AddCookie(fc)
		}
		page := httptest.NewRecorder()
		e.h.ServeHTTP(page, req)
		assert.Contain(t, "Cancel requested for 2 runs: #3, #4.", page.Body.String())
		var cleared bool
		for _, fc := range page.Result().Cookies() {
			cleared = cleared || (fc.Name == flashCookie && fc.MaxAge < 0)
		}
		assert.True(t, cleared)
	})
	t.Run("redirects back to a local referer only", func(t *testing.T) {
		e := newEnv(t)
		c := e.login(t, "Operator")

		for ref, want := range map[string]string{
			"http://other.test/scans?x=1": "/",
			"https://evil.test/x":          "/",
		} {
			req := httptest.NewRequest(http.MethodPost, "/scans/cancel-all", nil)
			req.Header.Set("Sec-Fetch-Site", "same-origin")
			req.Header.Set("Referer", ref)
			req.AddCookie(c)
			rec := httptest.NewRecorder()
			e.h.ServeHTTP(rec, req)
			assert.Equal(t, want, rec.Header().Get("Location"), ref)
		}
		req := httptest.NewRequest(http.MethodPost, "/scans/cancel-all", nil)
		req.Header.Set("Sec-Fetch-Site", "same-origin")
		req.Header.Set("Referer", "http://example.com/scans?x=1")
		req.Host = "example.com"
		req.AddCookie(c)
		rec := httptest.NewRecorder()
		e.h.ServeHTTP(rec, req)
		assert.Equal(t, "/scans?x=1", rec.Header().Get("Location"))
	})
}

func TestCancelAllConfirmInTopbar(t *testing.T) {
	e := newEnv(t)

	body := e.get("/", e.login(t, "Operator")).Body.String()

	assert.Contain(t, `action="/scans/cancel-all"`, body)
	assert.Contain(t, "data-confirm=", body)
	assert.NotContain(t, "onclick", body)
}

// sseClient connects to /events on a real server.
func sseClient(t *testing.T, e *testEnv, ctx context.Context, role string) *bufio.Reader {
	t.Helper()
	ts := httptest.NewServer(e.h)
	t.Cleanup(ts.Close)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/events", nil)
	assert.NoError(t, err)
	req.AddCookie(e.login(t, role))
	resp, err := http.DefaultClient.Do(req)
	assert.NoError(t, err)
	t.Cleanup(func() { resp.Body.Close() })
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "text/event-stream", resp.Header.Get("Content-Type"))
	return bufio.NewReader(resp.Body)
}

// readMessage returns the next SSE message (lines up to a blank line).
func readMessage(t *testing.T, r *bufio.Reader) string {
	t.Helper()
	var b strings.Builder
	for {
		line, err := r.ReadString('\n')
		assert.NoError(t, err)
		if line == "\n" {
			return b.String()
		}
		b.WriteString(line)
	}
}

func sseEnv(t *testing.T) *testEnv {
	t.Helper()
	e := newEnv(t)
	e.runner.events = make(chan runner.Event, 8)
	e.runner.unsub = make(chan struct{})
	return e
}

func TestSSEFragmentEscaped(t *testing.T) {
	e := sseEnv(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	r := sseClient(t, e, ctx, "Viewer")
	first := readMessage(t, r)
	assert.Contain(t, "event: live", first)
	assert.Contain(t, "No scan is running.", first)

	e.runner.events <- runner.Event{RunID: 9, Kind: runner.EventFinished, Progress: 1,
		Message: "<script>alert(1)</script>\nevent: evil"}
	msg := readMessage(t, r)

	assert.NotContain(t, "<script>", msg)
	assert.Contain(t, "&lt;script&gt;", msg)
	assert.Contain(t, "Scan #9 finished", msg)
	for _, line := range strings.Split(strings.TrimSpace(msg), "\n") {
		assert.True(t, strings.HasPrefix(line, "data: ") || line == "event: live", line)
	}
}

func TestSSEProgressAndCleanup(t *testing.T) {
	e := sseEnv(t)
	e.runner.active = []int64{5}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	r := sseClient(t, e, ctx, "Viewer")
	assert.Contain(t, "Scan #5 in progress", readMessage(t, r))

	e.runner.events <- runner.Event{RunID: 5, Kind: runner.EventProgress, Progress: 0.42, PPS: 612}
	msg := readMessage(t, r)

	assert.Contain(t, "42%", msg)
	assert.Contain(t, "612", msg)

	cancel()
	select {
	case <-e.runner.unsub:
	case <-time.After(3 * time.Second):
		t.Fatal("subscription not cleaned up after the client left")
	}
}

func TestSSERequiresPermission(t *testing.T) {
	e := sseEnv(t)
	ts := httptest.NewServer(e.h)
	defer ts.Close()

	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Get(ts.URL + "/events")
	assert.NoError(t, err)
	resp.Body.Close()

	assert.Equal(t, http.StatusSeeOther, resp.StatusCode)
}

func TestSSEStateBounded(t *testing.T) {
	st := &sseState{budget: 100}
	for i := int64(1); i <= 20; i++ {
		st.apply(runner.Event{RunID: i, Kind: runner.EventProgress, Progress: 0.5, PPS: 1000})
	}

	assert.Len(t, sseMaxRuns, st.runs)
	assert.Equal(t, 100, st.runs[0].PPSPct)
}

func TestSSEMessageFraming(t *testing.T) {
	got := string(sseMessage("live", []byte("a\r\nb\n\n")))

	assert.Equal(t, "event: live\ndata: a\ndata: b\n\n", got)
}
