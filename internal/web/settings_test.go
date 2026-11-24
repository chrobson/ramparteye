package web

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ctx42/testing/pkg/assert"

	"github.com/chrobson/ramparteye/internal/auth"
	"github.com/chrobson/ramparteye/internal/dojo"
	"github.com/chrobson/ramparteye/internal/store"
)

func withDojoEnv(u, token string) envOpt {
	return func(d *Deps) { d.Cfg.DojoURL, d.Cfg.DojoToken, d.Cfg.DojoProduct = u, token, "Campus network" }
}

func dojoForm() url.Values {
	return url.Values{"url": {"https://dojo.example:8443/"}, "token": {"s3cret-token-value"},
		"product_type": {"RampartEye"}, "product": {"Campus network"}, "engagement": {"Continuous discovery"},
		"auto_push": {"1"}}
}

func TestSettingsRedirectsToFirstTab(t *testing.T) {
	e := newEnv(t)

	rec := e.get("/settings", e.login(t, auth.RoleAdmin))

	assert.Equal(t, http.StatusSeeOther, rec.Code)
	assert.Equal(t, "/settings/scope", rec.Header().Get("Location"))
}

func TestSettingsScopeTab(t *testing.T) {
	e := newEnv(t, withScope("10.20.0.0/18", "192.168.5.0/24"))

	body := e.get("/settings/scope", e.login(t, auth.RoleAdmin)).Body.String()

	assert.Contain(t, "10.20.0.0/18", body)
	assert.Contain(t, "192.168.5.0/24", body)
	assert.Contain(t, "RAMPART_ALLOWED_CIDRS", body)
	assert.Contain(t, `href="/settings/integrations"`, body)
	assert.Contain(t, `href="/settings/users"`, body)
	assert.Contain(t, `href="/settings/audit"`, body)
}

func TestDojoSettingsAdminOnly(t *testing.T) {
	e := newEnv(t)
	c := e.login(t, auth.RoleOperator)

	assert.Equal(t, http.StatusForbidden, e.get("/settings/integrations", c).Code)
	assert.Equal(t, http.StatusForbidden, e.post("/settings/integrations", dojoForm(), c).Code)
	assert.Equal(t, http.StatusForbidden, e.post("/settings/integrations/test", nil, c).Code)
	assert.Equal(t, http.StatusForbidden, e.post("/settings/integrations/push", nil, c).Code)
	assert.Nil(t, e.st.admin.dojo)
	assert.Len(t, 0, e.pusher.pushed)
}

func TestDojoFormManagedByEnvReadOnly(t *testing.T) {
	e := newEnv(t, withDojoEnv("https://dojo.env.example", "env-token-0123"))
	c := e.login(t, auth.RoleAdmin)

	body := e.get("/settings/integrations", c).Body.String()

	assert.Contain(t, "Managed by environment", body)
	assert.Contain(t, `value="https://dojo.env.example"`, body)
	for _, name := range []string{"url", "token", "product_type", "product", "engagement", "auto_push", "close_missing"} {
		assert.Regexp(t, `<input[^>]*name="`+name+`"[^>]*disabled`, body)
	}
	assert.NotContain(t, "env-token-0123", body)

	rec := e.post("/settings/integrations", dojoForm(), c)
	assert.Equal(t, http.StatusConflict, rec.Code)
	assert.Nil(t, e.st.admin.dojo)
}

func TestDojoSaveStoresTokenSealed(t *testing.T) {
	e := newEnv(t)
	c := e.login(t, auth.RoleAdmin)

	rec := e.post("/settings/integrations", dojoForm(), c)

	assert.Equal(t, http.StatusSeeOther, rec.Code)
	assert.Equal(t, "/settings/integrations", rec.Header().Get("Location"))
	cfg := e.st.admin.dojo
	assert.Equal(t, "https://dojo.example:8443", cfg.URL)
	assert.Equal(t, "Campus network", cfg.Product)
	assert.True(t, cfg.AutoPush)
	assert.False(t, cfg.CloseMissing)
	assert.NotEmpty(t, cfg.TokenEnc)
	assert.NotContain(t, "s3cret-token-value", string(cfg.TokenEnc))
	a := e.st.lastAudit()
	assert.Equal(t, "dojo.settings", a.Action)
	assert.NotContain(t, "s3cret", fmt.Sprint(a.Details))

	body := e.get("/settings/integrations", c).Body.String()
	assert.NotContain(t, "s3cret-token-value", body)
	assert.Contain(t, "stored encrypted", body)

	// An empty token keeps the stored one; ClearToken removes it.
	f := dojoForm()
	f.Set("token", "")
	e.post("/settings/integrations", f, c)
	assert.NotEmpty(t, e.st.admin.dojo.TokenEnc)
	f.Set("clear_token", "1")
	e.post("/settings/integrations", f, c)
	assert.Empty(t, e.st.admin.dojo.TokenEnc)
}

func TestDojoSaveInvalidURL(t *testing.T) {
	e := newEnv(t)
	f := dojoForm()
	f.Set("url", "ftp://user:pw@dojo")

	rec := e.post("/settings/integrations", f, e.login(t, auth.RoleAdmin))

	assert.Equal(t, http.StatusUnprocessableEntity, rec.Code)
	assert.Contain(t, "http or https", rec.Body.String())
	assert.NotContain(t, "s3cret-token-value", rec.Body.String())
	assert.Nil(t, e.st.admin.dojo)
}

func TestDojoTestConnectionChecklist(t *testing.T) {
	e := newEnv(t)
	c := e.login(t, auth.RoleAdmin)
	e.post("/settings/integrations", dojoForm(), c)
	e.checker.res = dojo.CheckResult{Reachable: true, TokenValid: true, CanImport: true, ProductExists: true,
		Version: "2.39", User: "rampart-bot"}

	rec := e.post("/settings/integrations/test", nil, c)

	assert.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()
	assert.Equal(t, 4, strings.Count(body, `class="check-row ok"`))
	assert.Contain(t, "URL reachable (DefectDojo 2.39)", body)
	assert.Contain(t, "Token valid (user: rampart-bot)", body)
	assert.Contain(t, "Permission: import / reimport scan", body)
	assert.Contain(t, `Product &#34;Campus network&#34; exists`, body)
	assert.Equal(t, "s3cret-token-value", e.checker.token) // the stored token, opened
	assert.Equal(t, "Campus network", e.checker.product)
	assert.NotContain(t, "s3cret-token-value", body)
	assert.Equal(t, "dojo.test", e.st.lastAudit().Action)
}

func TestDojoTestConnectionFailure(t *testing.T) {
	e := newEnv(t)
	c := e.login(t, auth.RoleAdmin)
	e.post("/settings/integrations", dojoForm(), c)
	e.checker.res = dojo.CheckResult{Reachable: true}
	e.checker.err = errors.New("unexpected <b>answer</b> s3cret-token-value")

	body := e.post("/settings/integrations/test", nil, c).Body.String()

	assert.Equal(t, 1, strings.Count(body, `class="check-row ok"`))
	assert.Contain(t, `class="check-row bad"`, body)
	assert.Contain(t, "&lt;b&gt;answer&lt;/b&gt;", body)
	assert.NotContain(t, "s3cret-token-value", body)
}

func TestDojoTestConnectionWithoutToken(t *testing.T) {
	e := newEnv(t)
	c := e.login(t, auth.RoleAdmin)
	f := dojoForm()
	f.Set("token", "")
	e.post("/settings/integrations", f, c)

	body := e.post("/settings/integrations/test", nil, c).Body.String()

	assert.Contain(t, "Save an API token first", body)
	assert.Equal(t, "", e.checker.product)
}

func TestDojoPushLatestNow(t *testing.T) {
	e := newEnv(t)
	e.withPushResult(dojo.PushRecord{RunID: 6, Findings: 36, Added: 2, Closed: 4, OK: true}, nil)

	rec := e.post("/settings/integrations/push", nil, e.login(t, auth.RoleAdmin))

	assert.Equal(t, http.StatusSeeOther, rec.Code)
	assert.Equal(t, []string{"0:manual"}, e.pusher.pushed)
	assert.Nil(t, e.pusher.pushErrAtCall)
	assert.True(t, e.pusher.pushDeadline > 0)
	assert.Equal(t, "Pushed 36 findings of run #6 to DefectDojo: 2 new, 4 closed.", flashOf(t, rec))
	assert.Equal(t, "dojo.push", e.st.lastAudit().Action)
}

func TestDojoPushHistory(t *testing.T) {
	e := newEnv(t)
	run := func(id int64) *int64 { return &id }
	e.st.admin.pushes = []store.DojoPush{
		{RunID: run(6), At: testNow.Add(-2 * time.Minute), Endpoint: "reimport-scan", Findings: 36, Added: 2, Closed: 4, OK: true, Trigger: "auto"},
		{RunID: run(5), At: testNow.Add(-time.Hour), Skipped: true, Error: dojo.SkippedStale, Trigger: "auto"},
		{RunID: run(4), At: testNow.Add(-2 * time.Hour), Error: "401 <script>x</script>", Trigger: "manual"},
	}

	body := e.get("/settings/integrations", e.login(t, auth.RoleAdmin)).Body.String()

	assert.Contain(t, "#6", body)
	assert.Contain(t, "+2 / −4", body)
	assert.Contain(t, "reimported", body)
	assert.Contain(t, `class="push-skipped"`, body)
	assert.Contain(t, "skipped", body)
	assert.Contain(t, "401 &lt;script&gt;x&lt;/script&gt;", body)
	assert.NotContain(t, "<script>x</script>", body)
}

func TestTopbarDojoChipStates(t *testing.T) {
	yes, no := true, false
	cases := []struct {
		name  string
		chip  dojo.ChipState
		err   error
		want  string
		class string
	}{
		{"not configured", dojo.ChipState{}, nil, "DefectDojo · not configured", "chip-off"},
		{"connected", dojo.ChipState{Configured: true, LastOK: &yes, LastAt: testNow.Add(-2 * time.Minute), Findings: 36},
			nil, "DefectDojo · 36 findings · synced 2 min ago", "chip-ok"},
		{"failed", dojo.ChipState{Configured: true, LastOK: &no, LastAt: testNow}, nil, "DefectDojo · last push failed", "chip-bad"},
		{"status error", dojo.ChipState{}, errors.New("db down"), "DefectDojo · status unavailable", "chip-bad"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t)
			e.pusher.chip, e.pusher.err = c.chip, c.err

			admin := e.get("/", e.login(t, auth.RoleAdmin))
			viewer := e.get("/", e.st.session(e.st.addUser(t, "v", "correct-horse", auth.RoleViewer, false).ID))

			assert.Equal(t, http.StatusOK, admin.Code)
			assert.Contain(t, c.want, admin.Body.String())
			assert.Regexp(t, `<a href="/settings/integrations" class="chip `+c.class+`">`, admin.Body.String())
			assert.Contain(t, c.want, viewer.Body.String())
			assert.Contain(t, `<span class="chip `+c.class+`">`, viewer.Body.String())
		})
	}
}

func TestSettingsAuditLog(t *testing.T) {
	e := newEnv(t)
	c := e.login(t, auth.RoleAdmin)
	for i := 0; i < 60; i++ {
		e.st.audit = append(e.st.audit, auditEntry{Action: "user.create", Entity: "user:<b>x</b>"})
	}
	e.st.audit = append(e.st.audit, auditEntry{Action: "login.failed", Entity: "user:y"})

	body := e.get("/settings/audit", c).Body.String()
	assert.Contain(t, "login.failed", body)
	assert.Contain(t, "user:&lt;b&gt;x&lt;/b&gt;", body)
	assert.Contain(t, `href="/settings/audit?page=2"`, body)

	body = e.get("/settings/audit?action=login.failed", c).Body.String()
	assert.Equal(t, 1, strings.Count(body, "user:y"))
	assert.NotContain(t, "user:&lt;b&gt;", body)
	assert.NotContain(t, "page=2", body)

	body = e.get("/settings/audit?action=user.create&page=2", c).Body.String()
	assert.Equal(t, 10, strings.Count(body, "user:&lt;b&gt;x&lt;/b&gt;"))
}

func TestAuditNoOlderLinkAtLastPage(t *testing.T) {
	e := newEnv(t)
	e.st.admin.auditFull = true
	c := e.login(t, auth.RoleAdmin)

	assert.Contain(t, "Older", e.get("/settings/audit?page="+strconv.Itoa(maxAuditPage-1), c).Body.String())
	assert.NotContain(t, "Older", e.get("/settings/audit?page="+strconv.Itoa(maxAuditPage), c).Body.String())
}

func TestDojoTestConnectionHasDeadline(t *testing.T) {
	e := newEnv(t)
	c := e.login(t, auth.RoleAdmin)
	e.post("/settings/integrations", dojoForm(), c)

	e.post("/settings/integrations/test", nil, c)

	assert.True(t, e.checker.deadline > 0 && e.checker.deadline <= 15*time.Second)
}
