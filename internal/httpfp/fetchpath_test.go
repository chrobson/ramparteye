package httpfp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"

	"github.com/ctx42/testing/pkg/assert"
)

// recorder serves fixed responses and records what reached the server.
type recorder struct {
	mu   sync.Mutex
	reqs []*http.Request
}

func (rc *recorder) handler(w http.ResponseWriter, r *http.Request) {
	rc.mu.Lock()
	rc.reqs = append(rc.reqs, r)
	rc.mu.Unlock()
	switch r.URL.Path {
	case "/manager/html":
		w.Header().Set("WWW-Authenticate", `Basic realm="Tomcat Manager Application"`)
		w.Header().Set("X-Auth-Token", "SECRET")
		w.WriteHeader(http.StatusUnauthorized)
	case "/big":
		_, _ = w.Write([]byte(strings.Repeat("a", 2<<20)))
	case "/moved":
		http.Redirect(w, r, "/elsewhere", http.StatusFound)
	default:
		_, _ = w.Write([]byte("ok " + r.URL.RequestURI()))
	}
}

func (rc *recorder) all() []*http.Request {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	return append([]*http.Request(nil), rc.reqs...)
}

func newRecorder(t *testing.T) (*recorder, *httptest.Server) {
	t.Helper()
	rc := &recorder{}
	srv := httptest.NewServer(http.HandlerFunc(rc.handler))
	t.Cleanup(srv.Close)
	return rc, srv
}

func Test_HTTPProber_FetchPath(t *testing.T) {
	rc, srv := newRecorder(t)
	p := newProber(t, nil)
	hdr := http.Header{"Accept": {"application/json"}}

	resp, err := p.FetchPath(context.Background(), endpointFor(t, srv.URL, ""), http.MethodGet, "/manager/html", hdr)

	assert.NoError(t, err)
	assert.Equal(t, 401, resp.Status)
	assert.Equal(t, `Basic realm="Tomcat Manager Application"`, resp.Headers["Www-Authenticate"][0])
	assert.Equal(t, redacted, resp.Headers["X-Auth-Token"][0])
	reqs := rc.all()
	assert.Len(t, 1, reqs)
	assert.Equal(t, "GET", reqs[0].Method)
	assert.Equal(t, "application/json", reqs[0].Header.Get("Accept"))
	assert.Equal(t, DefaultUserAgent, reqs[0].Header.Get("User-Agent"))
}

func Test_HTTPProber_FetchPath_query_and_head(t *testing.T) {
	rc, srv := newRecorder(t)
	p := newProber(t, nil)
	ep := endpointFor(t, srv.URL, "")

	resp, err := p.FetchPath(context.Background(), ep, http.MethodGet, "/haproxy?stats", nil)
	assert.NoError(t, err)
	assert.Equal(t, "ok /haproxy?stats", string(resp.Body))

	resp, err = p.FetchPath(context.Background(), ep, http.MethodHead, "/x", nil)
	assert.NoError(t, err)
	assert.Equal(t, 200, resp.Status)
	assert.Len(t, 0, resp.Body)
	assert.Equal(t, "HEAD", rc.all()[1].Method)
}

func Test_HTTPProber_FetchPath_vhost_sends_host_header(t *testing.T) {
	rc, srv := newRecorder(t)
	p := newProber(t, nil)

	_, err := p.FetchPath(context.Background(), endpointFor(t, srv.URL, "app.lab.test"), http.MethodGet, "/x", nil)

	assert.NoError(t, err)
	assert.True(t, strings.HasPrefix(rc.all()[0].Host, "app.lab.test:"))
}

func Test_HTTPProber_FetchPath_does_not_follow_redirects(t *testing.T) {
	rc, srv := newRecorder(t)
	p := newProber(t, nil)

	resp, err := p.FetchPath(context.Background(), endpointFor(t, srv.URL, ""), http.MethodGet, "/moved", nil)

	assert.NoError(t, err)
	assert.Equal(t, 302, resp.Status)
	assert.Len(t, 1, rc.all())
}

func Test_HTTPProber_FetchPath_caps_body(t *testing.T) {
	_, srv := newRecorder(t)
	p := newProber(t, nil)

	resp, err := p.FetchPath(context.Background(), endpointFor(t, srv.URL, ""), http.MethodGet, "/big", nil)

	assert.NoError(t, err)
	assert.Len(t, DefaultMaxBody, resp.Body)
}

func Test_HTTPProber_FetchPath_refuses(t *testing.T) {
	tests := []struct {
		testN string

		method string
		path   string
		hdr    http.Header
		want   error
	}{
		{"post", http.MethodPost, "/x", nil, ErrMethodNotAllowed},
		{"put", http.MethodPut, "/x", nil, ErrMethodNotAllowed},
		{"empty path", http.MethodGet, "", nil, ErrBadPath},
		{"relative path", http.MethodGet, "x", nil, ErrBadPath},
		{"scheme relative", http.MethodGet, "//evil.test/x", nil, ErrBadPath},
		{"absolute url", http.MethodGet, "http://evil.test/x", nil, ErrBadPath},
		{"embedded url", http.MethodGet, "/x?u=http://evil.test", nil, ErrBadPath},
		{"traversal", http.MethodGet, "/a/../b", nil, ErrBadPath},
		{"encoded traversal", http.MethodGet, "/a/%2e%2e/b", nil, ErrBadPath},
		{"encoded slash", http.MethodGet, "/a%2Fb", nil, ErrBadPath},
		{"backslash", http.MethodGet, `/a\b`, nil, ErrBadPath},
		{"crlf", http.MethodGet, "/a\r\nX: y", nil, ErrBadPath},
		{"fragment", http.MethodGet, "/a#b", nil, ErrBadPath},
		{"space", http.MethodGet, "/a b", nil, ErrBadPath},
		{"too long", http.MethodGet, "/" + strings.Repeat("a", 300), nil, ErrBadPath},
		{"auth header", http.MethodGet, "/x", http.Header{"Authorization": {"Basic eDp4"}}, ErrBadHeader},
		{"cookie header", http.MethodGet, "/x", http.Header{"Cookie": {"a=b"}}, ErrBadHeader},
		{"host header", http.MethodGet, "/x", http.Header{"Host": {"evil.test"}}, ErrBadHeader},
		{"content-length", http.MethodGet, "/x", http.Header{"Content-Length": {"5"}}, ErrBadHeader},
		{"method override", http.MethodGet, "/x", http.Header{"X-Http-Method-Override": {"DELETE"}}, ErrBadHeader},
		{"x-http-method", http.MethodGet, "/x", http.Header{"X-Http-Method": {"PUT"}}, ErrBadHeader},
		{"x-method-override", http.MethodGet, "/x", http.Header{"X-Method-Override": {"POST"}}, ErrBadHeader},
		{"original url", http.MethodGet, "/x", http.Header{"X-Original-Url": {"/admin/login"}}, ErrBadHeader},
		{"rewrite url", http.MethodGet, "/x", http.Header{"X-Rewrite-Url": {"/admin/login"}}, ErrBadHeader},
		{"forwarded", http.MethodGet, "/x", http.Header{"Forwarded": {"for=127.0.0.1"}}, ErrBadHeader},
		{"x-forwarded-for", http.MethodGet, "/x", http.Header{"X-Forwarded-For": {"127.0.0.1"}}, ErrBadHeader},
		{"max-forwards", http.MethodGet, "/x", http.Header{"Max-Forwards": {"0"}}, ErrBadHeader},
		{"range", http.MethodGet, "/x", http.Header{"Range": {"bytes=0-1"}}, ErrBadHeader},
		{"encoded percent", http.MethodGet, "/a%252e%252e/b", nil, ErrBadPath},
		{"encoded newline", http.MethodGet, "/a%0d%0aX", nil, ErrBadPath},
		{"encoded control", http.MethodGet, "/a%1F", nil, ErrBadPath},
		{"encoded del", http.MethodGet, "/a%7F", nil, ErrBadPath},
	}
	for _, tt := range tests {
		t.Run(tt.testN, func(t *testing.T) {
			rc, srv := newRecorder(t)
			p := newProber(t, nil)

			_, err := p.FetchPath(context.Background(), endpointFor(t, srv.URL, ""), tt.method, tt.path, tt.hdr)

			assert.ErrorIs(t, tt.want, err)
			assert.Len(t, 0, rc.all())
		})
	}
}

func Test_HTTPProber_FetchPath_out_of_scope(t *testing.T) {
	rc, srv := newRecorder(t)
	p := newProber(t, nil)
	ep := endpointFor(t, srv.URL, "")
	ep.Key.IP = netip.MustParseAddr("10.0.0.1")

	_, err := p.FetchPath(context.Background(), ep, http.MethodGet, "/x", nil)

	assert.ErrorIs(t, ErrNotAllowed, err)
	assert.Len(t, 0, rc.all())
}

func Test_HTTPProber_FetchPath_bad_scheme(t *testing.T) {
	_, srv := newRecorder(t)
	p := newProber(t, nil)
	ep := endpointFor(t, srv.URL, "")
	ep.Scheme = "ftp"

	_, err := p.FetchPath(context.Background(), ep, http.MethodGet, "/x", nil)

	assert.ErrorContain(t, "unsupported scheme", err)
}

func Test_CheckProbeHeaders_allowlist(t *testing.T) {
	ok := http.Header{"Accept": {"a"}, "Accept-Language": {"en"}, "X-Requested-With": {"XMLHttpRequest"},
		"If-None-Match": {`"x"`}, "If-Modified-Since": {"Mon, 01 Jan 2024 00:00:00 GMT"}}

	assert.NoError(t, CheckProbeHeaders(ok))
	assert.NoError(t, CheckProbeHeaders(http.Header{"accept": {"a"}})) // case-insensitive
	assert.ErrorIs(t, ErrBadHeader, CheckProbeHeaders(http.Header{"X-Custom": {"a"}}))
}
