package web

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ctx42/testing/pkg/assert"
)

func TestHealthzOK(t *testing.T) {
	e := newMonEnv(t, &fakeMonitor{})

	rec := e.get("/healthz", nil)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "ok", rec.Body.String())
	assert.Contain(t, "text/plain", rec.Header().Get("Content-Type"))
	assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
	assert.Equal(t, "", rec.Header().Get("Location"))
	assert.Equal(t, 1, e.mon.count("Ping"))
}

func TestHealthzNeedsNoSessionAndSetsNoCookie(t *testing.T) {
	e := newMonEnv(t, &fakeMonitor{})

	rec := e.get("/healthz", nil)

	assert.Len(t, 0, rec.Result().Cookies())
	assert.Equal(t, 0, e.st.sessionCount())
}

func TestHealthzKeepsSecurityHeaders(t *testing.T) {
	h := newMonEnv(t, &fakeMonitor{}).get("/healthz", nil).Header()

	assert.Equal(t, "nosniff", h.Get("X-Content-Type-Options"))
	assert.Equal(t, "DENY", h.Get("X-Frame-Options"))
	assert.Contain(t, "default-src 'self'", h.Get("Content-Security-Policy"))
}

func TestHealthzHead(t *testing.T) {
	e := newMonEnv(t, &fakeMonitor{})
	req := httptest.NewRequest(http.MethodHead, "/healthz", nil)
	rec := httptest.NewRecorder()

	e.h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestHealthzDatabaseDownIsUnavailableWithoutDetails(t *testing.T) {
	m := &fakeMonitor{pingErr: errors.New("dial tcp 10.9.8.7:5432: connection refused")}
	e := newMonEnv(t, m)

	rec := e.get("/healthz", nil)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
	assert.Equal(t, "unavailable", rec.Body.String())
	assert.NotContain(t, "10.9.8.7", rec.Body.String())
	assert.NotContain(t, "10.9.8.7", rec.Header().Get("Content-Type"))
	assert.Contain(t, "connection refused", e.logs.String())
	assert.Contain(t, "healthz", e.logs.String())
}

func TestHealthzSlowDatabaseIsUnavailable(t *testing.T) {
	m := &fakeMonitor{block: true}
	e := newMonEnv(t, m)
	e.srv.healthTimeout = 20 * time.Millisecond

	start := time.Now()
	rec := e.get("/healthz", nil)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
	assert.Equal(t, "unavailable", rec.Body.String())
	assert.True(t, time.Since(start) < 2*time.Second)
	assert.Contain(t, "deadline exceeded", e.logs.String())
}

func TestHealthzDefaultTimeoutIsTwoSeconds(t *testing.T) {
	e := newMonEnv(t, &fakeMonitor{})

	assert.Equal(t, 2*time.Second, e.srv.healthTimeout)
}

func TestHealthzWithoutMonitorIsUnavailable(t *testing.T) {
	e := newEnv(t)

	rec := e.get("/healthz", nil)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}
