package web

import (
	"errors"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/ctx42/testing/pkg/assert"

	"github.com/chrobson/ramparteye/internal/auth"
	"github.com/chrobson/ramparteye/internal/dojo"
	"github.com/chrobson/ramparteye/internal/model"
	webassets "github.com/chrobson/ramparteye/web"
)

func TestSeverityClasses(t *testing.T) {
	cases := map[model.Severity]string{
		model.SevCritical: "sev-crit",
		model.SevHigh:     "sev-high",
		model.SevMedium:   "sev-med",
		model.SevLow:      "sev-low",
		model.SevInfo:     "sev-info",
		"":                "sev-info",
		"Bogus":           "sev-info",
	}
	for sev, want := range cases {
		assert.Equal(t, want, sevClass(sev), "severity %q", sev)
	}
}

func TestSeverityBadgeRendered(t *testing.T) {
	e := newEnvFS(t, overlay(t, map[string]string{
		"probe.html": `{{define "title"}}Probe{{end}}{{define "content"}}{{template "sev" .Data}}{{end}}`,
	}))
	req := withUser(httptest.NewRequest(http.MethodGet, "/", nil), auth.RoleViewer)
	rec := httptest.NewRecorder()

	e.srv.render(rec, req, "probe", model.SevCritical)

	assert.Contain(t, `class="sev sev-crit">Critical</span>`, rec.Body.String())
}

func TestChangeClasses(t *testing.T) {
	assert.Equal(t, "tag-new", changeClass(model.ChangeNew))
	assert.Equal(t, "tag-gone", changeClass(model.ChangeGone))
	assert.Equal(t, "tag-changed", changeClass(model.ChangeChanged))
	assert.Equal(t, "tag-up", changeClass(model.ChangeHostUp))
	assert.Equal(t, "tag-gone", changeClass(model.ChangeHostDown))
	assert.Equal(t, "tag-flap", changeClass(model.ChangeUnstable))
	assert.Equal(t, "tag-changed", changeClass("other"))
}

func TestAgo(t *testing.T) {
	ago := agoFunc(func() time.Time { return testNow })
	cases := []struct {
		at   time.Time
		want string
	}{
		{time.Time{}, "never"},
		{testNow.Add(-20 * time.Second), "just now"},
		{testNow.Add(time.Minute), "just now"},
		{testNow.Add(-2 * time.Minute), "2 min ago"},
		{testNow.Add(-3 * time.Hour), "3 h ago"},
		{testNow.Add(-50 * time.Hour), "2 d ago"},
	}
	for _, c := range cases {
		assert.Equal(t, c.want, ago(c.at), "at %v", c.at)
	}
}

func TestNumberFormat(t *testing.T) {
	assert.Equal(t, "0", num(0))
	assert.Equal(t, "999", num(999))
	assert.Equal(t, "5,000", num(5000))
	assert.Equal(t, "16,384", num(16384))
	assert.Equal(t, "1,234,567", num(1234567))
	assert.Equal(t, "-1,000", num(-1000))
}

func TestCanFunc(t *testing.T) {
	req := withUser(httptest.NewRequest(http.MethodGet, "/", nil), auth.RoleOperator)

	ok, err := can(req.Context(), "scans.run")
	assert.NoError(t, err)
	assert.True(t, ok)

	ok, err = can(req.Context(), "users.admin")
	assert.NoError(t, err)
	assert.False(t, ok)

	_, err = can(req.Context(), "scans.runn")
	assert.ErrorContain(t, "unknown permission", err)
}

func TestEscapesHostileTitle(t *testing.T) {
	hostile := `<script>alert(1)</script>`
	e := newEnvFS(t, overlay(t, map[string]string{
		"probe.html": `{{define "title"}}{{.Data.Title}}{{end}}{{define "content"}}
<table class="tbl"><tr><td>{{template "cell" (dict "Value" .Data.Title "Max" 12)}}</td><td>{{template "cell" (dict "Value" .Data.Title "Max" 200)}}</td></tr></table>
<a href="/assets/{{.Data.Title}}" title="{{.Data.Title}}">x</a>{{end}}`,
	}))
	req := withUser(httptest.NewRequest(http.MethodGet, "/", nil), auth.RoleViewer)
	rec := httptest.NewRecorder()

	e.srv.render(rec, req, "probe", struct{ Title string }{hostile})

	body := rec.Body.String()
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contain(t, "&lt;script&gt;alert(1)&lt;/script&gt;", body)
	assert.NotContain(t, "<script>alert", body)
	assert.Contain(t, "<details", body) // long value truncated, full value in details
}

func TestCellTruncatesOnRuneBoundary(t *testing.T) {
	assert.Equal(t, "hé", truncate("héllo", 2))
	assert.Equal(t, "abc", truncate("abc", 3))
	assert.Equal(t, "a�b", truncate("a\xffb", 10))
}

func TestNavGroups(t *testing.T) {
	e := newEnv(t)
	rec := e.get("/", e.login(t, auth.RoleAdmin))

	body := rec.Body.String()
	assert.Equal(t, http.StatusOK, rec.Code)
	labels := []string{">Observe<", ">Dashboard<", ">Scans<", ">Assets<", ">Changes<", ">Findings<",
		">Configure<", ">Signatures<", ">Scan profiles<", ">Import / export<", ">Settings<"}
	last := -1
	for _, l := range labels {
		i := strings.Index(body, l)
		assert.True(t, i > last, "%s missing or out of order", l)
		last = i
	}
	assert.Contain(t, `href="/" aria-current="page"`, body)
}

func TestNavHidesForbiddenItems(t *testing.T) {
	e := newEnv(t)
	body := e.get("/", e.login(t, auth.RoleViewer)).Body.String()

	assert.Contain(t, ">Dashboard<", body)
	assert.NotContain(t, ">Import / export<", body)
	assert.NotContain(t, ">Settings<", body)
}

func TestNavMarksActiveSection(t *testing.T) {
	nav := buildNav(withUser(httptest.NewRequest(http.MethodGet, "/assets/10.0.0.1", nil), auth.RoleAdmin))

	var active []string
	for _, g := range nav {
		for _, it := range g.Items {
			if it.Active {
				active = append(active, it.Label)
			}
		}
	}
	assert.Equal(t, []string{"Assets"}, active)
}

func TestLayoutHasSafetyStrip(t *testing.T) {
	e := newEnv(t)

	op := e.get("/", e.login(t, auth.RoleOperator)).Body.String()
	assert.Contain(t, "10.20.0.0/18", op)
	assert.Contain(t, "GET/HEAD only", op)
	assert.Contain(t, "5,000 pps", op)
	assert.Contain(t, "Cancel all scans", op)
	assert.Contain(t, `data-confirm=`, op)

	viewer := e.get("/", e.login(t, auth.RoleViewer)).Body.String()
	assert.Contain(t, "10.20.0.0/18", viewer)
	assert.Contain(t, "GET/HEAD only", viewer)
	assert.NotContain(t, "Cancel all scans", viewer)
}

func TestSafetyStripWithoutScope(t *testing.T) {
	e := newEnv(t, withScope())

	body := e.get("/", e.login(t, auth.RoleViewer)).Body.String()

	assert.Contain(t, "no scope set", body)
}

func TestScopeSummary(t *testing.T) {
	assert.Equal(t, "", scopeSummary(nil))
	assert.Equal(t, "10.0.0.0/24", scopeSummary([]string{"10.0.0.0/24"}))
	assert.Equal(t, "10.0.0.0/24, 10.1.0.0/24", scopeSummary([]string{"10.0.0.0/24", "10.1.0.0/24"}))
	assert.Equal(t, "10.0.0.0/24, 10.1.0.0/24 +2 more",
		scopeSummary([]string{"10.0.0.0/24", "10.1.0.0/24", "10.2.0.0/24", "10.3.0.0/24"}))
}

func TestScanChip(t *testing.T) {
	e := newEnv(t)
	c := e.login(t, auth.RoleViewer)

	assert.Contain(t, `class="chip chip-idle"><span aria-hidden="true">●</span>Idle</a>`, e.get("/", c).Body.String())

	e.runner.active = []int64{7}
	assert.Contain(t, "Scan #7 running", e.get("/", c).Body.String())

	e.runner.active = []int64{9, 7}
	assert.Contain(t, "2 scans running", e.get("/", c).Body.String())
}

func TestDojoChip(t *testing.T) {
	yes, no := true, false
	cases := []struct {
		name string
		chip dojo.ChipState
		err  error
		want string
		kind string
	}{
		{"off", dojo.ChipState{}, nil, "DefectDojo · not configured", "chip-off"},
		{"fresh", dojo.ChipState{Configured: true}, nil, "DefectDojo · no pushes yet", "chip-off"},
		{"ok", dojo.ChipState{Configured: true, LastOK: &yes, LastAt: testNow.Add(-2 * time.Minute), Findings: 36},
			nil, "DefectDojo · 36 findings · synced 2 min ago", "chip-ok"},
		{"failed", dojo.ChipState{Configured: true, LastOK: &no, LastAt: testNow}, nil, "DefectDojo · last push failed", "chip-bad"},
		{"error", dojo.ChipState{}, errors.New("db down"), "DefectDojo · status unavailable", "chip-bad"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := dojoChip(c.chip, c.err, agoFunc(func() time.Time { return testNow }))

			assert.Equal(t, c.want, got.Text)
			assert.Equal(t, c.kind, got.Kind)
		})
	}
}

func TestThemeToggleAndAssets(t *testing.T) {
	e := newEnv(t)
	body := e.get("/", e.login(t, auth.RoleViewer)).Body.String()

	assert.Contain(t, `id="theme-toggle"`, body)
	assert.Regexp(t, `src="/static/app\.js\?v=[0-9a-f]{12}"`, body)
	assert.Regexp(t, `href="/static/app\.css\?v=[0-9a-f]{12}"`, body)
	assert.Contain(t, `id="confirm-dialog"`, body)
	assert.NotContain(t, "<script>", body) // no inline scripts (CSP)
}

func TestUserChip(t *testing.T) {
	e := newEnv(t)
	body := e.get("/", e.login(t, auth.RoleAnalyst)).Body.String()

	assert.Contain(t, "analyst · Analyst", body)
	assert.Contain(t, `action="/logout"`, body)
	assert.Contain(t, `href="/account/password"`, body)
}

// polish matches the Polish diacritics ą ć ę ł ń ó ś ź ż (either case).
var polish = regexp.MustCompile("[\u0105\u0107\u0119\u0142\u0144\u00f3\u015b\u017a\u017c\u0104\u0106\u0118\u0141\u0143\u00d3\u015a\u0179\u017b]")

func TestNoPolishInTemplates(t *testing.T) {
	check := func(fsys fs.FS, exts ...string) {
		err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			for _, ext := range exts {
				if strings.HasSuffix(p, ext) {
					b, err := fs.ReadFile(fsys, p)
					if err != nil {
						return err
					}
					assert.False(t, polish.Match(b), "Polish characters in %s", p)
				}
			}
			return nil
		})
		assert.NoError(t, err)
	}
	check(webassets.Templates, ".html")
	check(webassets.Static, "app.js")
}

func TestRenderFailureGives500(t *testing.T) {
	e := newEnvFS(t, overlay(t, map[string]string{
		"broken.html": `{{define "title"}}Broken{{end}}{{define "content"}}{{.Data.Missing}}{{end}}`,
	}))
	req := withUser(httptest.NewRequest(http.MethodGet, "/", nil), auth.RoleViewer)
	rec := httptest.NewRecorder()

	e.srv.render(rec, req, "broken", struct{}{})

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.Contain(t, "Something went wrong", rec.Body.String())
	assert.NotContain(t, "Missing", rec.Body.String()) // no template internals leaked
}

// withUser returns r carrying a user of the built-in role.
func withUser(r *http.Request, role string) *http.Request {
	u := auth.User{ID: 1, Login: strings.ToLower(role), RoleName: role, Perms: auth.BuiltinRoles[role]}
	return r.WithContext(auth.WithUser(r.Context(), u))
}
