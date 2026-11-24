package web

import (
	"errors"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/ctx42/testing/pkg/assert"

	"github.com/chrobson/ramparteye/internal/auth"
	"github.com/chrobson/ramparteye/internal/config"
	webassets "github.com/chrobson/ramparteye/web"
)

func TestSecurityHeaders(t *testing.T) {
	e := newEnv(t)

	for _, path := range []string{"/login", "/static/app.css", "/nope"} {
		h := e.get(path, nil).Header()

		assert.Equal(t, "nosniff", h.Get("X-Content-Type-Options"), path)
		assert.Equal(t, "DENY", h.Get("X-Frame-Options"), path)
		assert.Equal(t, "same-origin", h.Get("Referrer-Policy"), path)
		csp := h.Get("Content-Security-Policy")
		assert.Contain(t, "default-src 'self'", csp, path)
		assert.Contain(t, "frame-ancestors 'none'", csp, path)
		assert.Contain(t, "script-src 'self';", csp, path)
		assert.Contain(t, "object-src 'none'", csp, path)
		assert.Contain(t, "base-uri 'none'", csp, path)
		assert.Contain(t, "form-action 'self'", csp, path)
	}
}

func TestCSPHasNoInlineScripts(t *testing.T) {
	csp := newEnv(t).get("/login", nil).Header().Get("Content-Security-Policy")

	for _, d := range strings.Split(csp, ";") {
		d = strings.TrimSpace(d)
		if strings.HasPrefix(d, "script-src") || strings.HasPrefix(d, "default-src") {
			assert.NotContain(t, "unsafe-inline", d)
			assert.NotContain(t, "unsafe-eval", d)
		}
	}
}

func TestInstanceHeader(t *testing.T) {
	e := newEnv(t)
	want := InstanceID(config.Config{SecretKey: []byte("0123456789abcdef0123456789abcdef")})

	for _, path := range []string{"/login", "/static/app.js", "/nope", "/"} {
		assert.Equal(t, want, e.get(path, nil).Header().Get(InstanceHeader), path)
	}
	assert.Equal(t, "X-Rampart-Instance", InstanceHeader)
}

func TestInstanceID(t *testing.T) {
	a := InstanceID(config.Config{SecretKey: []byte("key-a")})
	b := InstanceID(config.Config{SecretKey: []byte("key-b")})
	db := InstanceID(config.Config{DatabaseURL: "postgres://x"})

	assert.Len(t, 24, a)
	assert.Equal(t, a, InstanceID(config.Config{SecretKey: []byte("key-a"), DatabaseURL: "postgres://y"}))
	assert.NotEqual(t, a, b)
	assert.NotEqual(t, a, db)
	assert.NotContain(t, "key-a", a)
}

func TestStaticFiles(t *testing.T) {
	e := newEnv(t)

	css := e.get("/static/app.css", nil)
	assert.Equal(t, http.StatusOK, css.Code)
	assert.Contain(t, "text/css", css.Header().Get("Content-Type"))
	assert.Contain(t, "max-age", css.Header().Get("Cache-Control"))

	for _, f := range []string{"/static/app.js", "/static/htmx.min.js", "/static/htmx-sse.js"} {
		assert.Equal(t, http.StatusOK, e.get(f, nil).Code, f)
	}
	assert.Equal(t, http.StatusNotFound, e.get("/static/", nil).Code)
	assert.Equal(t, http.StatusNotFound, e.get("/static/missing.js", nil).Code)
}

func TestBrandIcons(t *testing.T) {
	e := newEnv(t)

	page := e.get("/login", nil).Body.String()
	assert.Contain(t, `<link rel="icon" type="image/svg+xml" href="/static/favicon.svg?v=`, page)
	assert.Contain(t, `<img src="/static/logo.svg?v=`, page)
	for _, f := range []string{"/static/favicon.svg", "/static/logo.svg"} {
		res := e.get(f, nil)
		assert.Equal(t, http.StatusOK, res.Code, f)
		assert.Contain(t, "image/svg+xml", res.Header().Get("Content-Type"), f)
	}
}

func TestNotFoundThemed(t *testing.T) {
	e := newEnv(t)

	anon := e.get("/nope", nil)
	assert.Equal(t, http.StatusNotFound, anon.Code)
	assert.Contain(t, "Page not found", anon.Body.String())
	assert.NotContain(t, ">Observe<", anon.Body.String())

	in := e.get("/nope", e.login(t, auth.RoleViewer))
	assert.Equal(t, http.StatusNotFound, in.Code)
	assert.Contain(t, "Page not found", in.Body.String())
	assert.Contain(t, ">Observe<", in.Body.String())
}

func TestForbiddenThemed(t *testing.T) {
	e := newEnv(t)

	rec := e.get("/exchange", e.login(t, auth.RoleViewer))

	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Contain(t, "Access denied", rec.Body.String())
	assert.Contain(t, "export", rec.Body.String())
	assert.Contain(t, ">Observe<", rec.Body.String())
}

func TestForbiddenHTMX(t *testing.T) {
	e := newEnv(t)
	req := httptest.NewRequest(http.MethodGet, "/exchange", nil)
	req.AddCookie(e.login(t, auth.RoleViewer))
	req.Header.Set("HX-Request", "true")
	rec := httptest.NewRecorder()

	e.h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.NotContain(t, "<html", rec.Body.String())
}

func TestPagesByPermission(t *testing.T) {
	e := newEnv(t)
	admin := e.login(t, auth.RoleAdmin)

	for _, p := range []string{"/", "/scans", "/assets", "/changes", "/findings",
		"/signatures", "/profiles", "/exchange", "/settings/scope"} {
		rec := e.get(p, admin)
		assert.Equal(t, http.StatusOK, rec.Code, p)
		assert.Contain(t, `class="panel`, rec.Body.String(), p)
	}
	assert.Equal(t, http.StatusForbidden, e.get("/settings", e.login(t, auth.RoleOperator)).Code)
}

func TestAnonymousRedirectsToLogin(t *testing.T) {
	e := newEnv(t)

	rec := e.get("/scans?x=1", nil)
	assert.Equal(t, http.StatusSeeOther, rec.Code)
	assert.Equal(t, "/login?next=%2Fscans%3Fx%3D1", rec.Header().Get("Location"))

	req := httptest.NewRequest(http.MethodGet, "/scans", nil)
	req.Header.Set("HX-Request", "true")
	hx := httptest.NewRecorder()
	e.h.ServeHTTP(hx, req)
	assert.Equal(t, http.StatusUnauthorized, hx.Code)
	assert.Equal(t, "/login", hx.Header().Get("HX-Redirect"))
}

func TestPanicGives500(t *testing.T) {
	e := newEnv(t)
	h := e.srv.recoverer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("boom") }))
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", nil))

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.Contain(t, "Something went wrong", rec.Body.String())
	assert.NotContain(t, "boom", rec.Body.String())
}

func TestClientIP(t *testing.T) {
	trusted := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	cases := []struct {
		name    string
		remote  string
		xff     []string
		trusted []netip.Prefix
		want    string
	}{
		{"bare ipv4", "203.0.113.5:4444", nil, nil, "203.0.113.5"},
		{"bare ipv6", "[2001:db8::1]:4444", nil, nil, "2001:db8::1"},
		{"mapped", "[::ffff:203.0.113.5]:1", nil, nil, "203.0.113.5"},
		{"no port", "203.0.113.5", nil, nil, "203.0.113.5"},
		{"xff ignored without trusted proxies", "203.0.113.5:1", []string{"198.51.100.7"}, nil, "203.0.113.5"},
		{"xff ignored from untrusted peer", "203.0.113.5:1", []string{"198.51.100.7"}, trusted, "203.0.113.5"},
		{"xff from trusted proxy", "10.0.0.2:1", []string{"198.51.100.7"}, trusted, "198.51.100.7"},
		{"rightmost untrusted hop wins", "10.0.0.2:1", []string{"6.6.6.6, 198.51.100.7, 10.0.0.9"}, trusted, "198.51.100.7"},
		{"multiple headers", "10.0.0.2:1", []string{"6.6.6.6", "198.51.100.7"}, trusted, "198.51.100.7"},
		{"garbage stops the walk", "10.0.0.2:1", []string{"198.51.100.7, junk"}, trusted, "10.0.0.2"},
		{"all hops trusted", "10.0.0.2:1", []string{"10.0.0.3"}, trusted, "10.0.0.3"},
		{"xff with port", "10.0.0.2:1", []string{"198.51.100.7:555"}, trusted, "10.0.0.2"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = c.remote
			for _, v := range c.xff {
				req.Header.Add("X-Forwarded-For", v)
			}

			assert.Equal(t, c.want, clientIP(req, c.trusted))
		})
	}
}

func TestSafeNext(t *testing.T) {
	cases := map[string]string{
		"":                       "/",
		"/scans":                 "/scans",
		"/assets/10.0.0.1?x=1":   "/assets/10.0.0.1?x=1",
		"//evil.example":         "/",
		"/\\evil.example":        "/",
		"https://evil.example/":  "/",
		"evil":                   "/",
		"/ok\r\nSet-Cookie: x=1": "/",
		"/%2F%2Fevil":            "/%2F%2Fevil",
		"/\tevil":                "/",
	}
	for in, want := range cases {
		assert.Equal(t, want, safeNext(in), "next %q", in)
	}
}

func TestStaticCacheOnlyOnSuccess(t *testing.T) {
	e := newEnv(t)

	assert.Equal(t, "", e.get("/static/missing.js", nil).Header().Get("Cache-Control"))
	assert.Equal(t, "", e.get("/static/", nil).Header().Get("Cache-Control"))
	assert.Contain(t, "max-age", e.get("/static/app.js", nil).Header().Get("Cache-Control"))
}

func TestNewServerFailsOnUnreadableStatic(t *testing.T) {
	d := newEnv(t).srv.d
	_, err := newServerFS(d, webassets.Templates, badFS{}, time.Now)

	assert.ErrorContain(t, "static", err)
}

// badFS fails every operation.
type badFS struct{}

func (badFS) Open(string) (fs.File, error) { return nil, errors.New("disk on fire") }
