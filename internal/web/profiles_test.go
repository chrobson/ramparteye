package web

import (
	"errors"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/ctx42/testing/pkg/assert"

	"github.com/chrobson/ramparteye/internal/auth"
	"github.com/chrobson/ramparteye/internal/model"
	"github.com/chrobson/ramparteye/internal/runner"
	"github.com/chrobson/ramparteye/internal/scope"
	"github.com/chrobson/ramparteye/internal/store"
)

// profileForm is a valid scan profile form.
func profileForm() url.Values {
	return url.Values{
		"name": {"Lab weekly"}, "all_targets": {"1"}, "port_profile": {"top"}, "top_ports": {"1000"},
		"max_rate": {"1000"}, "workers": {"4"}, "window_start": {"22:00"}, "window_end": {"06:00"},
		"every_minutes": {"1440"}, "enabled": {"1"}, "extra_ports": {"1"},
	}
}

func profilesEnv(t *testing.T) *testEnv {
	t.Helper()
	e := newEnv(t)
	e.st.dash.targets = []model.Target{{ID: 1, Kind: model.TargetCIDR, Value: "10.20.0.0/24", Tags: []string{"lab"}},
		{ID: 2, Kind: model.TargetIP, Value: "10.20.9.9"}}
	return e
}

func TestProfileRateCapped(t *testing.T) {
	e := profilesEnv(t)
	f := profileForm()
	f.Set("max_rate", "9000")

	rec := e.post("/profiles", f, e.login(t, auth.RoleOperator))

	assert.Equal(t, http.StatusUnprocessableEntity, rec.Code)
	assert.Contain(t, "5000", rec.Body.String())
	assert.Contain(t, "packets/s", rec.Body.String())
	assert.Contain(t, `value="Lab weekly"`, rec.Body.String())
	assert.Len(t, 0, e.st.scans.configs)
}

func TestProfileCreate(t *testing.T) {
	e := profilesEnv(t)

	rec := e.post("/profiles", profileForm(), e.login(t, auth.RoleOperator))

	assert.Equal(t, http.StatusSeeOther, rec.Code)
	assert.Equal(t, "/profiles", rec.Header().Get("Location"))
	assert.Equal(t, `Scan profile "Lab weekly" saved.`, flashOf(t, rec))
	assert.Len(t, 1, e.st.scans.configs)
	c := e.st.scans.configs[0]
	assert.Equal(t, "Lab weekly", c.Name)
	assert.Equal(t, 1000, c.MaxRate)
	assert.Equal(t, 4, c.Workers)
	assert.Equal(t, 1000, c.TopPorts)
	assert.Equal(t, runner.ProfileTop, c.PortProfile)
	assert.True(t, c.ExtraPorts)
	assert.True(t, c.Enabled)
	assert.Equal(t, 22*time.Hour, *c.WindowStart)
	assert.Equal(t, 6*time.Hour, *c.WindowEnd)
	assert.Equal(t, 1440, *c.EveryMinutes)
	assert.Len(t, 0, c.TargetIDs)
	assert.Equal(t, "scan_config.save", e.st.lastAudit().Action)
}

func TestProfileCreateSelectedTargetsAndList(t *testing.T) {
	e := profilesEnv(t)
	f := profileForm()
	f.Del("all_targets")
	f["target_ids"] = []string{"2"}
	f.Set("port_profile", "list")
	f.Set("ports", "22, 80,443,8000-8002")
	f.Del("window_start")
	f.Del("window_end")
	f.Del("every_minutes")

	rec := e.post("/profiles", f, e.login(t, auth.RoleOperator))

	assert.Equal(t, http.StatusSeeOther, rec.Code)
	c := e.st.scans.configs[0]
	assert.Equal(t, []int64{2}, c.TargetIDs)
	assert.Equal(t, "22,80,443,8000-8002", c.Ports)
	assert.Nil(t, c.WindowStart)
	assert.Nil(t, c.EveryMinutes)
}

func TestProfileValidation(t *testing.T) {
	cases := map[string]struct {
		field, value string
		want         string
	}{
		"empty name":      {"name", "  ", "Name is required"},
		"rate zero":       {"max_rate", "0", "between 1 and 5000"},
		"rate not number": {"max_rate", "fast", "between 1 and 5000"},
		"bad port":        {"ports", "70000", "invalid port"},
		"bad extra":       {"extra_port_list", "1-x", "invalid port"},
		"bad profile":     {"port_profile", "everything", "Unknown port profile"},
		"bad top":         {"top_ports", "0", "between 1 and 65535"},
		"workers":         {"workers", "65", "between 1 and 64"},
		"window start":    {"window_start", "25:00", "HH:MM"},
		"half window":     {"window_end", "", "both a start and an end"},
		"every too short": {"every_minutes", "2", "between 5 and 44640"},
		"unknown target":  {"target_ids", "77", "unknown target"},
		"no targets":      {"all_targets", "", "Choose targets"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			e := profilesEnv(t)
			f := profileForm()
			if c.field == "ports" {
				f.Set("port_profile", "list")
			}
			if c.field == "target_ids" {
				f.Del("all_targets")
			}
			f.Set(c.field, c.value)

			rec := e.post("/profiles", f, e.login(t, auth.RoleOperator))

			assert.Equal(t, http.StatusUnprocessableEntity, rec.Code)
			assert.Contain(t, c.want, rec.Body.String())
			assert.Len(t, 0, e.st.scans.configs)
		})
	}
}

func TestProfileListPortsMustBeAllowed(t *testing.T) {
	e := newEnv(t, func(d *Deps) { d.Cfg.ScanPorts = []int{22, 80} })
	f := profileForm()
	f.Set("port_profile", "list")
	f.Set("ports", "443,8443")

	rec := e.post("/profiles", f, e.login(t, auth.RoleOperator))

	assert.Equal(t, http.StatusUnprocessableEntity, rec.Code)
	assert.Contain(t, "RAMPART_SCAN_PORTS", rec.Body.String())
}

func TestProfileNameTaken(t *testing.T) {
	e := profilesEnv(t)
	e.st.scans.configs = []store.ScanConfig{{ID: 1, Name: "Lab weekly", MaxRate: 100, TopPorts: 100}}
	e.st.scans.nextCfg = 1

	rec := e.post("/profiles", profileForm(), e.login(t, auth.RoleOperator))

	assert.Equal(t, http.StatusUnprocessableEntity, rec.Code)
	assert.Contain(t, "already exists", rec.Body.String())
}

func TestProfileEdit(t *testing.T) {
	e := profilesEnv(t)
	e.st.scans.configs = []store.ScanConfig{{ID: 3, Name: "Old", MaxRate: 100, TopPorts: 100, Workers: 1}}
	c := e.login(t, auth.RoleOperator)

	page := e.get("/profiles/3", c)
	assert.Equal(t, http.StatusOK, page.Code)
	assert.Contain(t, `value="Old"`, page.Body.String())
	assert.Contain(t, `action="/profiles/3"`, page.Body.String())

	rec := e.post("/profiles/3", profileForm(), c)

	assert.Equal(t, http.StatusSeeOther, rec.Code)
	assert.Equal(t, "Lab weekly", e.st.scans.configs[0].Name)
	assert.Equal(t, int64(3), e.st.scans.configs[0].ID)
}

func TestProfileEditUnknown(t *testing.T) {
	e := profilesEnv(t)
	c := e.login(t, auth.RoleOperator)

	assert.Equal(t, http.StatusNotFound, e.get("/profiles/9", c).Code)
	assert.Equal(t, http.StatusNotFound, e.get("/profiles/x", c).Code)
	assert.Equal(t, http.StatusNotFound, e.post("/profiles/9", profileForm(), c).Code)
}

func TestProfilesList(t *testing.T) {
	e := profilesEnv(t)
	every := 60
	ws, we := 22*time.Hour, 6*time.Hour
	e.st.scans.configs = []store.ScanConfig{{ID: 3, Name: "Night <b>", MaxRate: 800, TopPorts: 1000, Workers: 2,
		WindowStart: &ws, WindowEnd: &we, EveryMinutes: &every, Enabled: true, PortProfile: runner.ProfileTop}}

	op := e.get("/profiles", e.login(t, auth.RoleOperator)).Body.String()
	assert.Contain(t, "Night &lt;b&gt;", op)
	assert.Contain(t, "22:00–06:00", op)
	assert.Contain(t, "every 60 min", op)
	assert.Contain(t, "Run now", op)
	assert.Contain(t, `href="/profiles/new"`, op)

	viewer := e.get("/profiles", e.login(t, auth.RoleViewer))
	assert.Equal(t, http.StatusOK, viewer.Code)
	assert.NotContain(t, "Run now", viewer.Body.String())
	assert.NotContain(t, `href="/profiles/new"`, viewer.Body.String())
}

func TestProfileWritesNeedScansRun(t *testing.T) {
	e := profilesEnv(t)
	e.st.scans.configs = []store.ScanConfig{{ID: 3, Name: "Old"}}
	c := e.login(t, auth.RoleAnalyst)

	assert.Equal(t, http.StatusForbidden, e.get("/profiles/new", c).Code)
	assert.Equal(t, http.StatusForbidden, e.post("/profiles", profileForm(), c).Code)
	assert.Equal(t, http.StatusForbidden, e.post("/profiles/3/run", nil, c).Code)
	assert.Equal(t, http.StatusForbidden, e.post("/profiles/3/delete", nil, c).Code)
	assert.Len(t, 0, e.runner.started)
}

func TestProfileRunNow(t *testing.T) {
	e := profilesEnv(t)
	e.st.scans.configs = []store.ScanConfig{{ID: 3, Name: "Lab"}}
	e.runner.startRun = 12

	rec := e.post("/profiles/3/run", nil, e.login(t, auth.RoleOperator))

	assert.Equal(t, http.StatusSeeOther, rec.Code)
	assert.Equal(t, "/scans/12", rec.Header().Get("Location"))
	assert.Equal(t, []int64{3}, e.runner.started)
	assert.Equal(t, "Scan #12 started.", flashOf(t, rec))
	assert.Equal(t, "scan.start", e.st.lastAudit().Action)
}

func TestProfileRunNowErrors(t *testing.T) {
	cases := map[string]struct {
		err  error
		want string
	}{
		"no scope": {scope.ErrNoScope, "No scan scope configured"},
		"busy":     {runner.ErrAlreadyRunning, "already running"},
		"empty":    {runner.ErrNoTargets, "no targets inside the scan scope"},
		"other":    {errors.New("db down"), "The scan could not be started"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			e := profilesEnv(t)
			e.st.scans.configs = []store.ScanConfig{{ID: 3, Name: "Lab"}}
			e.runner.startErr = c.err

			rec := e.post("/profiles/3/run", nil, e.login(t, auth.RoleOperator))

			assert.Equal(t, http.StatusSeeOther, rec.Code)
			assert.Equal(t, "/profiles", rec.Header().Get("Location"))
			assert.Contain(t, c.want, flashOf(t, rec))
		})
	}
}

func TestProfileRunNowWithoutRunner(t *testing.T) {
	e := newEnv(t, func(d *Deps) { d.Runner = nil })
	e.st.scans.configs = []store.ScanConfig{{ID: 3, Name: "Lab"}}

	rec := e.post("/profiles/3/run", nil, e.login(t, auth.RoleOperator))

	assert.Equal(t, http.StatusSeeOther, rec.Code)
	assert.Contain(t, "No scan runner", flashOf(t, rec))
}

func TestProfileDelete(t *testing.T) {
	e := profilesEnv(t)
	e.st.scans.configs = []store.ScanConfig{{ID: 3, Name: "Lab"}}
	c := e.login(t, auth.RoleOperator)

	rec := e.post("/profiles/3/delete", nil, c)

	assert.Equal(t, http.StatusSeeOther, rec.Code)
	assert.Len(t, 0, e.st.scans.configs)
	assert.Equal(t, `Scan profile "Lab" deleted.`, flashOf(t, rec))

	e.st.scans.configs = []store.ScanConfig{{ID: 4, Name: "Busy"}}
	e.st.scans.deleteErr = store.ErrScanConfigBusy
	rec = e.post("/profiles/4/delete", nil, c)
	assert.Contain(t, "unfinished run", flashOf(t, rec))
}
