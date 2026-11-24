package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/ctx42/testing/pkg/assert"

	"github.com/chrobson/ramparteye/internal/auth"
)

func loginForm(login, pw, next string) url.Values {
	return url.Values{"login": {login}, "password": {pw}, "next": {next}}
}

func TestLoginPage(t *testing.T) {
	e := newEnv(t)

	rec := e.get(`/login?next=/scans"><b>`, nil)

	body := rec.Body.String()
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contain(t, `action="/login"`, body)
	assert.Contain(t, `name="password"`, body)
	assert.Contain(t, `value="/scans&#34;&gt;&lt;b&gt;"`, body)
	assert.NotContain(t, ">Observe<", body)
}

func TestLoginSuccess(t *testing.T) {
	e := newEnv(t)
	u := e.st.addUser(t, "admin", "correct-horse", auth.RoleAdmin, false)

	rec := e.post("/login", loginForm("admin", "correct-horse", "/scans"), nil)

	assert.Equal(t, http.StatusSeeOther, rec.Code)
	assert.Equal(t, "/scans", rec.Header().Get("Location"))
	c := sessionCookie(rec)
	assert.NotNil(t, c)
	assert.True(t, c.HttpOnly)
	assert.Equal(t, 1, e.st.sessionCount())
	a := e.st.lastAudit()
	assert.Equal(t, "login", a.Action)
	assert.Equal(t, u.ID, *a.UserID)
	assert.Equal(t, map[string]any{"ip": "203.0.113.5"}, a.Details)

	// The new session works.
	assert.Equal(t, http.StatusOK, e.get("/", c).Code)
}

func TestLoginUsesForwardedIPFromTrustedProxy(t *testing.T) {
	e := newEnv(t, withTrustedProxies("203.0.113.0/24"))
	e.st.addUser(t, "admin", "correct-horse", auth.RoleAdmin, false)
	req := httptest.NewRequest(http.MethodPost, "/login",
		strings.NewReader(loginForm("admin", "wrong-password", "").Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Forwarded-For", "198.51.100.7")
	req.RemoteAddr = "203.0.113.5:4444"
	rec := httptest.NewRecorder()

	e.h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Equal(t, map[string]any{"login": "admin", "ip": "198.51.100.7"}, e.st.lastAudit().Details)
}

func TestLoginOpenRedirectGuard(t *testing.T) {
	e := newEnv(t)
	e.st.addUser(t, "admin", "correct-horse", auth.RoleAdmin, false)

	for _, next := range []string{"//evil.example", "/\\evil.example", "https://evil.example", "javascript:alert(1)"} {
		rec := e.post("/login", loginForm("admin", "correct-horse", next), nil)

		assert.Equal(t, http.StatusSeeOther, rec.Code, next)
		assert.Equal(t, "/", rec.Header().Get("Location"), next)
	}
}

func TestLoginPageRedirectsWhenLoggedIn(t *testing.T) {
	e := newEnv(t)

	rec := e.get("/login?next=//evil.example", e.login(t, auth.RoleViewer))

	assert.Equal(t, http.StatusSeeOther, rec.Code)
	assert.Equal(t, "/", rec.Header().Get("Location"))
}

func TestLoginBadCredentials(t *testing.T) {
	e := newEnv(t)
	e.st.addUser(t, "admin", "correct-horse", auth.RoleAdmin, false)

	rec := e.post("/login", loginForm("admin", "wrong-password", "/scans"), nil)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Contain(t, "Invalid login or password.", rec.Body.String())
	assert.Contain(t, `value="admin"`, rec.Body.String())
	assert.Nil(t, sessionCookie(rec))
	assert.Equal(t, 0, e.st.sessionCount())
	assert.Equal(t, "login.failed", e.st.lastAudit().Action)
	assert.Nil(t, e.st.lastAudit().UserID)
}

func TestLoginLockout(t *testing.T) {
	e := newEnv(t)
	e.st.addUser(t, "admin", "correct-horse", auth.RoleAdmin, false)
	for range auth.MaxLoginFailures {
		e.post("/login", loginForm("admin", "wrong-password", ""), nil)
	}

	rec := e.post("/login", loginForm("admin", "correct-horse", ""), nil)

	assert.Equal(t, http.StatusTooManyRequests, rec.Code)
	assert.NotEqual(t, "", rec.Header().Get("Retry-After"))
	assert.Contain(t, "Too many failed logins", rec.Body.String())
	assert.Equal(t, 0, e.st.sessionCount())
}

func TestLoginCSRF(t *testing.T) {
	e := newEnv(t)
	e.st.addUser(t, "admin", "correct-horse", auth.RoleAdmin, false)

	cross := httptest.NewRequest(http.MethodPost, "/login",
		strings.NewReader(loginForm("admin", "correct-horse", "").Encode()))
	cross.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	cross.Header.Set("Sec-Fetch-Site", "cross-site")
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, cross)
	assert.Equal(t, http.StatusForbidden, rec.Code)

	origin := httptest.NewRequest(http.MethodPost, "/login",
		strings.NewReader(loginForm("admin", "correct-horse", "").Encode()))
	origin.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	origin.Header.Set("Origin", "https://evil.example")
	rec = httptest.NewRecorder()
	e.h.ServeHTTP(rec, origin)
	assert.Equal(t, http.StatusForbidden, rec.Code)

	assert.Equal(t, 0, e.st.sessionCount())
	assert.Len(t, 0, e.st.auditActions())
}

func TestLogout(t *testing.T) {
	e := newEnv(t)
	c := e.login(t, auth.RoleViewer)

	rec := e.post("/logout", nil, c)

	assert.Equal(t, http.StatusSeeOther, rec.Code)
	assert.Equal(t, "/login", rec.Header().Get("Location"))
	assert.Equal(t, 0, e.st.sessionCount())
	assert.Equal(t, -1, sessionCookie(rec).MaxAge)
	assert.Equal(t, "logout", e.st.lastAudit().Action)
	assert.Equal(t, http.StatusSeeOther, e.get("/", c).Code)
}

func TestLogoutRejectsCrossSite(t *testing.T) {
	e := newEnv(t)
	c := e.login(t, auth.RoleViewer)
	req := httptest.NewRequest(http.MethodPost, "/logout", nil)
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	req.AddCookie(c)
	rec := httptest.NewRecorder()

	e.h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Equal(t, 1, e.st.sessionCount())
}

func pwForm(cur, nw, confirm string) url.Values {
	return url.Values{"current": {cur}, "new": {nw}, "confirm": {confirm}}
}

func TestForcedPasswordChange(t *testing.T) {
	e := newEnv(t)
	u := e.st.addUser(t, "admin", "initial-pass", auth.RoleAdmin, true)
	c := e.st.session(u.ID)

	rec := e.get("/", c)
	assert.Equal(t, http.StatusSeeOther, rec.Code)
	assert.Equal(t, auth.PasswordPath, rec.Header().Get("Location"))

	page := e.get(auth.PasswordPath, c)
	assert.Equal(t, http.StatusOK, page.Code)
	assert.Contain(t, "You must set a new password", page.Body.String())
	assert.NotContain(t, ">Observe<", page.Body.String())

	cases := []struct {
		form url.Values
		msg  string
	}{
		{pwForm("wrong-pass", "new-password-1", "new-password-1"), "Current password is incorrect."},
		{pwForm("initial-pass", "new-password-1", "new-password-2"), "The new passwords do not match."},
		{pwForm("initial-pass", "short", "short"), "at least 8 characters"},
		{pwForm("initial-pass", strings.Repeat("x", 73), strings.Repeat("x", 73)), "at most 72 bytes"},
		{pwForm("initial-pass", "initial-pass", "initial-pass"), "must differ from the current one"},
	}
	for _, tc := range cases {
		rec := e.post(auth.PasswordPath, tc.form, c)
		assert.Equal(t, http.StatusUnprocessableEntity, rec.Code, tc.msg)
		assert.Contain(t, tc.msg, rec.Body.String())
		assert.True(t, e.st.user(u.ID).MustChangePassword)
	}

	ok := e.post(auth.PasswordPath, pwForm("initial-pass", "new-password-1", "new-password-1"), c)
	assert.Equal(t, http.StatusSeeOther, ok.Code)
	assert.Equal(t, "/", ok.Header().Get("Location"))
	got := e.st.user(u.ID)
	assert.False(t, got.MustChangePassword)
	assert.True(t, auth.CheckPassword(got.PasswordHash, "new-password-1"))
	assert.Equal(t, "user.password", e.st.lastAudit().Action)
	assert.Equal(t, u.ID, *e.st.lastAudit().UserID)

	assert.Equal(t, http.StatusOK, e.get("/", sessionCookie(ok)).Code)
}

func TestVoluntaryPasswordChangeUsesShell(t *testing.T) {
	e := newEnv(t)

	rec := e.get(auth.PasswordPath, e.login(t, auth.RoleViewer))

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contain(t, ">Observe<", rec.Body.String())
	assert.NotContain(t, "You must set a new password", rec.Body.String())
}

func TestPasswordPageRequiresLogin(t *testing.T) {
	e := newEnv(t)

	rec := e.get(auth.PasswordPath, nil)
	assert.Equal(t, http.StatusSeeOther, rec.Code)
	assert.Equal(t, "/login?next=%2Faccount%2Fpassword", rec.Header().Get("Location"))

	post := e.post(auth.PasswordPath, pwForm("a", "b", "b"), nil)
	assert.Equal(t, http.StatusSeeOther, post.Code)
	assert.Equal(t, "/login?next=%2F", post.Header().Get("Location"))
}

func TestPasswordChangeRevokesOtherSessions(t *testing.T) {
	e := newEnv(t)
	u := e.st.addUser(t, "admin", "initial-pass", auth.RoleAdmin, false)
	current, other := e.st.session(u.ID), e.st.session(u.ID)

	rec := e.post(auth.PasswordPath, pwForm("initial-pass", "new-password-1", "new-password-1"), current)

	assert.Equal(t, http.StatusSeeOther, rec.Code)
	fresh := sessionCookie(rec)
	assert.NotNil(t, fresh)
	assert.NotEqual(t, current.Value, fresh.Value)
	assert.Equal(t, http.StatusSeeOther, e.get("/", other).Code)
	assert.Equal(t, http.StatusSeeOther, e.get("/", current).Code)
	assert.Equal(t, http.StatusOK, e.get("/", fresh).Code)
	assert.Equal(t, 1, e.st.sessionCount())
}

func TestPasswordChangeThrottlesWrongCurrent(t *testing.T) {
	e := newEnv(t)
	u := e.st.addUser(t, "admin", "initial-pass", auth.RoleAdmin, false)
	c := e.st.session(u.ID)
	for range auth.MaxLoginFailures {
		rec := e.post(auth.PasswordPath, pwForm("wrong-pass", "new-password-1", "new-password-1"), c)
		assert.Equal(t, http.StatusUnprocessableEntity, rec.Code)
	}
	assert.Equal(t, "user.password.failed", e.st.lastAudit().Action)

	rec := e.post(auth.PasswordPath, pwForm("initial-pass", "new-password-1", "new-password-1"), c)

	assert.Equal(t, http.StatusTooManyRequests, rec.Code)
	assert.NotEqual(t, "", rec.Header().Get("Retry-After"))
	assert.True(t, auth.CheckPassword(e.st.user(u.ID).PasswordHash, "initial-pass"))
}

func TestLoginLockedIsAudited(t *testing.T) {
	e := newEnv(t)
	e.st.addUser(t, "admin", "correct-horse", auth.RoleAdmin, false)
	for range auth.MaxLoginFailures {
		e.post("/login", loginForm("admin", "wrong-password", ""), nil)
	}

	e.post("/login", loginForm("admin", "correct-horse", ""), nil)

	a := e.st.lastAudit()
	assert.Equal(t, "login.locked", a.Action)
	assert.Equal(t, map[string]any{"login": "admin", "ip": "203.0.113.5"}, a.Details)
}

func TestLoginReplacesExistingSession(t *testing.T) {
	e := newEnv(t)
	u := e.st.addUser(t, "admin", "correct-horse", auth.RoleAdmin, false)
	old := e.st.session(u.ID)

	rec := e.post("/login", loginForm("admin", "correct-horse", ""), old)

	assert.Equal(t, http.StatusSeeOther, rec.Code)
	assert.Equal(t, 1, e.st.sessionCount())
	assert.Equal(t, http.StatusSeeOther, e.get("/", old).Code)
	assert.Equal(t, http.StatusOK, e.get("/", sessionCookie(rec)).Code)
}
