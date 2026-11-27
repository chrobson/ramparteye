package web

import (
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/ctx42/testing/pkg/assert"

	"github.com/chrobson/ramparteye/internal/auth"
	"github.com/chrobson/ramparteye/internal/store"
)

func notifyForm(hook string) url.Values {
	return url.Values{"enabled": {"1"}, "url": {hook}, "format": {"slack"}, "secret": {"sign-SECRET-value"},
		"only_changes": {"1"}, "notify_failed": {"1"}, "base_url": {"https://rampart.example/"}}
}

func TestNotifySettingsAdminOnly(t *testing.T) {
	e := newNotifyEnv(t)
	c := e.login(t, auth.RoleOperator)

	assert.Equal(t, http.StatusForbidden, e.get("/settings/notifications", c).Code)
	assert.Equal(t, http.StatusForbidden, e.post("/settings/notifications", notifyForm(e.hook.url()), c).Code)
	assert.Equal(t, http.StatusForbidden, e.post("/settings/notifications/test", nil, c).Code)
	assert.Nil(t, e.nst.cfg.URLEnc)
	assert.Equal(t, 0, e.hook.count())
}

func TestNotifyTabInSettings(t *testing.T) {
	e := newNotifyEnv(t)

	body := e.get("/settings/scope", e.login(t, auth.RoleAdmin)).Body.String()

	assert.Contain(t, `href="/settings/notifications"`, body)
}

func TestNotifyPageDefaults(t *testing.T) {
	e := newNotifyEnv(t)

	rec := e.get("/settings/notifications", e.login(t, auth.RoleAdmin))

	assert.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()
	assert.Contain(t, `aria-current="page">Notifications`, body)
	assert.Regexp(t, `<input[^>]*name="only_changes"[^>]*checked`, body)
	assert.False(t, regexp.MustCompile(`<input[^>]*name="enabled"[^>]*checked`).MatchString(body))
	assert.Regexp(t, `<option value="json" selected>`, body)
	assert.Contain(t, "No notifications sent yet.", body)
	assert.Contain(t, "off", body)
}

func TestNotifySaveStoresCredentialsSealed(t *testing.T) {
	e := newNotifyEnv(t)
	c := e.login(t, auth.RoleAdmin)

	rec := e.post("/settings/notifications", notifyForm(e.hook.url()), c)

	assert.Equal(t, http.StatusSeeOther, rec.Code)
	assert.Equal(t, "/settings/notifications", rec.Header().Get("Location"))
	cfg := e.nst.cfg
	assert.True(t, cfg.Enabled)
	assert.Equal(t, "slack", cfg.Format)
	assert.Equal(t, e.hook.srv.URL, cfg.Endpoint)
	assert.Equal(t, "https://rampart.example", cfg.BaseURL)
	assert.NotEmpty(t, cfg.URLEnc)
	assert.NotEmpty(t, cfg.SecretEnc)
	assert.NotContain(t, "SECRET", string(cfg.URLEnc)+string(cfg.SecretEnc))
	a := e.st.lastAudit()
	assert.Equal(t, "notify.settings", a.Action)
	assert.Equal(t, "notify_config", a.Entity)
	details := fmt.Sprint(a.Details)
	assert.NotContain(t, "SECRET", details)
	assert.NotContain(t, "hooks/", details)
	assert.Contain(t, "url_changed:true", details)

	body := e.get("/settings/notifications", c).Body.String()
	assert.NotContain(t, "SECRET", body)
	assert.NotContain(t, "hooks/", body)
	assert.Contain(t, "stored encrypted", body)
	assert.Contain(t, e.hook.srv.URL, body) // scheme and host only
	assert.Regexp(t, `<input[^>]*name="url"[^>]*value=""`, body)
	assert.Regexp(t, `<input[^>]*name="secret"[^>]*value=""`, body)
	assert.Contain(t, `value="https://rampart.example"`, body)
	assert.Regexp(t, `<option value="slack" selected>`, body)
	assert.Regexp(t, `<input[^>]*name="notify_failed"[^>]*checked`, body)

	// Empty fields keep the stored values; the checkboxes remove them.
	f := notifyForm("")
	f.Set("secret", "")
	e.post("/settings/notifications", f, c)
	assert.NotEmpty(t, e.nst.cfg.URLEnc)
	assert.NotEmpty(t, e.nst.cfg.SecretEnc)
	f.Set("clear_secret", "1")
	e.post("/settings/notifications", f, c)
	assert.Empty(t, e.nst.cfg.SecretEnc)
	f.Del("enabled")
	f.Set("clear_url", "1")
	e.post("/settings/notifications", f, c)
	assert.Empty(t, e.nst.cfg.URLEnc)
	assert.Contain(t, "url_cleared:true", fmt.Sprint(e.st.lastAudit().Details))
}

func TestNotifySaveInvalidURL(t *testing.T) {
	e := newNotifyEnv(t)
	f := notifyForm("ftp://user:pw@hooks.example/SECRETPATH")

	rec := e.post("/settings/notifications", f, e.login(t, auth.RoleAdmin))

	assert.Equal(t, http.StatusUnprocessableEntity, rec.Code)
	body := rec.Body.String()
	assert.Contain(t, "http or https", body)
	assert.NotContain(t, "SECRET", body)
	assert.NotContain(t, "user:pw", body)
	assert.Regexp(t, `<option value="slack" selected>`, body) // the rest of the form is kept
	assert.Contain(t, `value="https://rampart.example/"`, body)
	assert.Nil(t, e.nst.cfg.URLEnc)
}

func TestNotifyEnableWithoutURL(t *testing.T) {
	e := newNotifyEnv(t)
	f := notifyForm("")

	rec := e.post("/settings/notifications", f, e.login(t, auth.RoleAdmin))

	assert.Equal(t, http.StatusUnprocessableEntity, rec.Code)
	assert.Contain(t, "Set a webhook URL to enable notifications.", rec.Body.String())
	assert.False(t, e.nst.cfg.Enabled)
}

func TestNotifySendTest(t *testing.T) {
	e := newNotifyEnv(t)
	c := e.login(t, auth.RoleAdmin)
	e.post("/settings/notifications", notifyForm(e.hook.url()), c)

	rec := e.post("/settings/notifications/test", nil, c)

	assert.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()
	assert.Equal(t, 1, e.hook.count())
	assert.Contain(t, `class="check-row ok"`, body)
	assert.Contain(t, "Test notification delivered (HTTP 204)", body)
	assert.NotContain(t, "SECRET", body)
	a := e.st.lastAudit()
	assert.Equal(t, "notify.test", a.Action)
	assert.Contain(t, "ok:true", fmt.Sprint(a.Details))
	// The history shows the test.
	assert.Regexp(t, `<td class="font-mono">test</td>`, body)
	assert.Contain(t, "delivered", body)
}

func TestNotifySendTestFailure(t *testing.T) {
	e := newNotifyEnv(t)
	c := e.login(t, auth.RoleAdmin)
	e.post("/settings/notifications", notifyForm(e.hook.url()), c)
	e.hook.mu.Lock()
	e.hook.status = http.StatusNotFound
	e.hook.mu.Unlock()

	body := e.post("/settings/notifications/test", nil, c).Body.String()

	assert.Contain(t, `class="check-row bad"`, body)
	assert.Contain(t, "HTTP 404 Not Found", body)
	assert.NotContain(t, "SECRET", body)
	assert.NotContain(t, "hooks/", body)
	assert.Contain(t, "ok:false", fmt.Sprint(e.st.lastAudit().Details))
	assert.Contain(t, "last delivery failed", body)
}

func TestNotifySendTestNotConfigured(t *testing.T) {
	e := newNotifyEnv(t)

	body := e.post("/settings/notifications/test", nil, e.login(t, auth.RoleAdmin)).Body.String()

	assert.Contain(t, "Save a webhook URL first.", body)
	assert.Equal(t, 0, e.hook.count())
}

func TestNotifyHistoryRows(t *testing.T) {
	e := newNotifyEnv(t)
	run, ok, bad := int64(42), 204, 503
	e.nst.deliveries = []store.NotifyDelivery{
		{RunID: &run, At: testNow, Trigger: "auto", Event: "scan.finished", Attempts: 1, Status: &ok, OK: true},
		{RunID: &run, At: testNow, Trigger: "auto", Event: "scan.failed", Attempts: 3, Status: &bad,
			Error: "https://hooks.example: HTTP 503 Service Unavailable"},
	}

	body := e.get("/settings/notifications", e.login(t, auth.RoleAdmin)).Body.String()

	assert.Contain(t, "#42", body)
	assert.Contain(t, "scan.failed", body)
	assert.Contain(t, "HTTP 503 Service Unavailable", body)
	assert.Contain(t, "3 attempts", body)
	assert.Equal(t, 1, strings.Count(body, `class="push-ok"`))
	assert.Equal(t, 1, strings.Count(body, `class="push-bad"`))
}

func TestNotifyWithoutNotifier(t *testing.T) {
	e := newEnv(t)
	c := e.login(t, auth.RoleAdmin)

	assert.Contain(t, "not available", e.get("/settings/notifications", c).Body.String())
	assert.Contain(t, "not available", e.post("/settings/notifications/test", nil, c).Body.String())
}
