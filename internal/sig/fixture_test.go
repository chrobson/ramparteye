package sig

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ctx42/testing/pkg/assert"
	"github.com/ctx42/testing/pkg/must"

	"github.com/chrobson/ramparteye/internal/httpfp"
	"github.com/chrobson/ramparteye/internal/model"
	"github.com/chrobson/ramparteye/internal/scan"
)

// route is one canned HTTP response of a fixture site.
type route struct {
	status   int
	ctype    string
	file     string // under testdata/fixtures
	body     string // used when file is empty
	location string
	cookies  []string
}

// fixtureSite serves routes over a real httptest server (unknown paths are
// 404 "404 page not found", like Go and Traefik defaults) and records every
// request method and path.
func fixtureSite(t *testing.T, routes map[string]route) (*httptest.Server, func() []string) {
	t.Helper()
	var mu sync.Mutex
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Method+" "+r.URL.RequestURI())
		mu.Unlock()
		rt, ok := routes[r.URL.RequestURI()]
		if !ok {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte("404 page not found\n"))
			return
		}
		for _, c := range rt.cookies {
			w.Header().Add("Set-Cookie", c)
		}
		if rt.ctype != "" {
			w.Header().Set("Content-Type", rt.ctype)
		}
		if rt.location != "" {
			w.Header().Set("Location", rt.location)
		}
		body := []byte(rt.body)
		if rt.file != "" {
			b, err := os.ReadFile(filepath.Join("testdata", "fixtures", rt.file))
			if err != nil {
				t.Error(err)
			}
			body = b
		}
		st := rt.status
		if st == 0 {
			st = http.StatusOK
		}
		w.WriteHeader(st)
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return srv, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(seen)
	}
}

// serviceFor converts an httptest server URL into a service observation.
func serviceFor(t *testing.T, rawURL string) model.ServiceObs {
	t.Helper()
	host, port, err := net.SplitHostPort(strings.TrimPrefix(rawURL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	p := must.Value(strconv.Atoi(port))
	return model.ServiceObs{ID: 1, Key: model.AssetKey{IP: netip.MustParseAddr(host), Port: uint16(p), Proto: "tcp"}, Banner: "http"}
}

// labSigIDs are the signatures written for the lab; a fixture must match
// exactly the expected subset of them (no false positives).
var labSigIDs = []string{"dvwa", "nginx-proxy-manager", "traefik-dashboard", "toxiproxy-api", "rabbitmq-management",
	"rabbitmq-amqp", "httpbin", "redis", "redis-noauth", "ftp", "vsftpd", "postgresql", "mysql",
	"wordpress", "adminer", "gitea", "phpmyadmin"}

type wantDet struct {
	id       string
	severity model.Severity
	version  string // "" = not checked
	outdated bool
}

// detSeverity is the export severity of a detection: the signature's
// (evidence "severity"), else the category default. DefectDojo export
// (Task 16) uses the same rule.
func detSeverity(d model.Detection) model.Severity {
	if s := d.Evidence["severity"]; s != "" {
		return model.Severity(s)
	}
	switch d.Category {
	case "admin-panel", "staging":
		return model.SevMedium
	}
	return model.SevInfo
}

func checkDetections(t *testing.T, ds []model.Detection, want []wantDet) {
	t.Helper()
	got := map[string]model.Detection{}
	for _, d := range ds {
		got[d.SignatureID] = d
	}
	var wantIDs, gotIDs []string
	for _, w := range want {
		wantIDs = append(wantIDs, w.id)
		d, ok := got[w.id]
		if !ok {
			continue
		}
		assert.Equal(t, w.severity, detSeverity(d), "%s: evidence %v", w.id, d.Evidence)
		if w.version != "" {
			assert.Equal(t, w.version, d.Evidence["version"], "%s: evidence %v", w.id, d.Evidence)
		}
		assert.Equal(t, w.outdated, d.Evidence["outdated"] != "", "%s: outdated %q", w.id, d.Evidence["outdated"])
	}
	for id := range got {
		if slices.Contains(labSigIDs, id) {
			gotIDs = append(gotIDs, id)
		}
	}
	sort.Strings(wantIDs)
	sort.Strings(gotIDs)
	assert.Equal(t, wantIDs, gotIDs)
}

func TestHTTPSignatureFixtures(t *testing.T) {
	html := "text/html; charset=UTF-8"
	tests := []struct {
		testN string

		routes map[string]route
		want   []wantDet
		probes []string // extra requests that must have been sent
		never  []string // requests that must not have been sent
	}{
		{testN: "dvwa", routes: map[string]route{
			"/":          {status: 302, location: "login.php", cookies: []string{"PHPSESSID=8a1c2d3e4f; path=/", "security=impossible; path=/"}},
			"/login.php": {ctype: html, file: "dvwa/login.html"},
		}, want: []wantDet{{id: "dvwa", severity: model.SevHigh}}},
		{testN: "nginx-proxy-manager", routes: map[string]route{
			"/":     {ctype: html, file: "nginx-proxy-manager/index.html"},
			"/api/": {ctype: "application/json; charset=utf-8", file: "nginx-proxy-manager/api.json"},
		}, want: []wantDet{{id: "nginx-proxy-manager", severity: model.SevMedium, version: "2"}}, probes: []string{"GET /api/"}},
		{testN: "traefik-api-insecure", routes: map[string]route{
			"/":            {status: 302, location: "/dashboard/", ctype: html, body: `<a href="/dashboard/">Found</a>.`},
			"/dashboard/":  {ctype: html, file: "traefik/dashboard.html"},
			"/api/version": {ctype: "application/json", file: "traefik/version.json"},
		}, want: []wantDet{{id: "traefik-dashboard", severity: model.SevHigh, version: "2.10.7"}}, probes: []string{"GET /api/version"}},
		{testN: "toxiproxy-api", routes: map[string]route{
			"/proxies": {ctype: "application/json", file: "toxiproxy/proxies.json"},
		}, want: []wantDet{{id: "toxiproxy-api", severity: model.SevHigh}}, probes: []string{"GET /proxies"}},
		{testN: "toxiproxy-api-empty", routes: map[string]route{
			"/proxies": {ctype: "application/json", body: "{}"},
		}, want: []wantDet{{id: "toxiproxy-api", severity: model.SevHigh}}},
		{testN: "rabbitmq-management", routes: map[string]route{
			"/": {ctype: html, file: "rabbitmq/index.html"},
		}, want: []wantDet{{id: "rabbitmq-management", severity: model.SevMedium}}},
		{testN: "httpbin", routes: map[string]route{
			"/": {ctype: html, file: "httpbin/index.html"},
		}, want: []wantDet{{id: "httpbin", severity: model.SevLow, version: "0.9.2"}}},
		{testN: "wordpress-4.7-not-installed", routes: map[string]route{
			"/":                      {status: 302, location: "/wp-admin/install.php"},
			"/wp-admin/install.php":  {ctype: html, file: "wordpress-4.7-install/install.html"},
			"/wp-admin/install.php/": {status: 404},
		}, want: []wantDet{{id: "wordpress", severity: model.SevHigh, version: "4.7", outdated: true}},
			never: []string{"GET /readme.html", "GET /feed/"}},
		{testN: "wordpress-5.8-generator", routes: map[string]route{
			"/": {ctype: html, file: "wordpress-5.8/home.html", cookies: []string{"wordpress_test_cookie=WP+Cookie+check; path=/"}},
		}, want: []wantDet{{id: "wordpress", severity: model.SevHigh, version: "5.8.3", outdated: true}}},
		{testN: "wordpress-version-from-readme", routes: map[string]route{
			"/":            {ctype: html, file: "wordpress-readme/home.html"},
			"/readme.html": {ctype: html, file: "wordpress-readme/readme.html"},
		}, want: []wantDet{{id: "wordpress", severity: model.SevHigh, version: "4.7", outdated: true}}, probes: []string{"GET /readme.html"}},
		{testN: "wordpress-current", routes: map[string]route{
			"/": {ctype: html, body: `<html><head><title>Blog</title><meta name="generator" content="WordPress 6.6.2" /></head><body><link href="/wp-content/x.css"></body></html>`},
		}, want: []wantDet{{id: "wordpress", severity: model.SevInfo, version: "6.6.2"}}, never: []string{"GET /readme.html"}},
		{testN: "adminer", routes: map[string]route{
			"/": {ctype: html, file: "adminer/index.html", cookies: []string{"adminer_key=0f1e2d3c; path=/; HttpOnly", "adminer_sid=9a8b7c; path=/; HttpOnly"}},
		}, want: []wantDet{{id: "adminer", severity: model.SevMedium}}},
		{testN: "gitea", routes: map[string]route{
			"/": {ctype: html, file: "gitea/index.html", cookies: []string{"i_like_gitea=6c1e4f2a9b; Path=/; HttpOnly; SameSite=Lax"}},
		}, want: []wantDet{{id: "gitea", severity: model.SevInfo}}},
		{testN: "phpmyadmin", routes: map[string]route{
			"/": {ctype: html, file: "phpmyadmin/index.html", cookies: []string{"phpMyAdmin=4f2b1c; path=/; HttpOnly; SameSite=Strict"}},
		}, want: []wantDet{{id: "phpmyadmin", severity: model.SevMedium}}},
		{testN: "plain-nginx-no-false-positives", routes: map[string]route{
			"/": {ctype: html, body: "<!DOCTYPE html><html><head><title>Welcome to nginx!</title></head><body><h1>Welcome to nginx!</h1></body></html>"},
		}, want: nil, never: []string{"GET /proxies", "GET /api/version", "GET /readme.html", "GET /feed/", "GET /api/"}},
	}
	sigs := builtins(t)
	for _, tt := range tests {
		t.Run(tt.testN, func(t *testing.T) {
			srv, seen := fixtureSite(t, tt.routes)
			s := serviceFor(t, srv.URL)
			prober := httpfp.New(httpfp.Options{Timeout: 5 * time.Second, SkipFavicon: true, Scope: loopbackScope(t)})
			obs, err := prober.Probe(context.Background(), model.Endpoint{ServiceID: 1, Key: s.Key, Scheme: "http"})
			if !assert.NoError(t, err) {
				return
			}

			ds := NewEngine(sigs, NewHTTPFetcher(prober)).Match(context.Background(), s, obs)

			checkDetections(t, ds, tt.want)
			reqs := seen()
			for _, r := range reqs {
				assert.True(t, strings.HasPrefix(r, "GET ") || strings.HasPrefix(r, "HEAD "), "non GET/HEAD request %q", r)
			}
			for _, want := range tt.probes {
				assert.Has(t, want, reqs)
			}
			for _, bad := range tt.never {
				assert.HasNo(t, bad, reqs)
			}
		})
	}
}

// End-to-end: the real prober and HTTPFetcher against an httptest server.
func TestHTTPFetcherWithProber(t *testing.T) {
	var mu sync.Mutex
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Method+" "+r.URL.Path)
		mu.Unlock()
		switch r.URL.Path {
		case "/":
			w.Header().Set("Server", "Apache-Coyote/1.1")
			_, _ = w.Write([]byte("<html><title>Apache Tomcat/9.0.83</title></html>"))
		case "/manager/html":
			w.Header().Set("WWW-Authenticate", `Basic realm="Tomcat Manager Application"`)
			w.WriteHeader(http.StatusUnauthorized)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	s := serviceFor(t, srv.URL)
	prober := httpfp.New(httpfp.Options{Timeout: 5 * time.Second, SkipFavicon: true, Scope: loopbackScope(t)})
	obs := must.Value(prober.Probe(context.Background(), model.Endpoint{ServiceID: 1, Key: s.Key, Scheme: "http"}))

	found := map[string]model.Detection{}
	for _, d := range NewEngine(builtins(t), NewHTTPFetcher(prober)).Match(context.Background(), s, obs) {
		found[d.SignatureID] = d
	}

	assert.HasKey(t, "tomcat", found)
	assert.HasKey(t, "tomcat-manager", found)
	assert.Contain(t, "401", found["tomcat-manager"].Evidence["path:/manager/html"])
	mu.Lock()
	defer mu.Unlock()
	for _, r := range seen {
		assert.True(t, strings.HasPrefix(r, "GET ") || strings.HasPrefix(r, "HEAD "), "non GET/HEAD request %q", r)
	}
	assert.True(t, len(seen) <= 1+9, "too many requests: %v", seen)
}

func TestHTTPFetcherOutOfScope(t *testing.T) {
	a := mustParse(t, "id: a1\nname: A\ncategory: other\nconfidence: 5\nmatchers:\n  - {type: path, path: /admin, status: [200]}\n")
	prober := httpfp.New(httpfp.Options{Timeout: time.Second, SkipFavicon: true, Scope: loopbackScope(t)})
	f := NewHTTPFetcher(prober)

	_, err := f.Fetch(context.Background(), svc(80, ""), httpObs(80, "", "", nil), ProbeRequest{Method: "GET", Path: "/admin"})

	assert.ErrorIs(t, httpfp.ErrNotAllowed, err)
	assert.Len(t, 0, NewEngine([]*Signature{a}, f).Match(context.Background(), svc(80, ""), httpObs(80, "", "", nil)))
}

func TestServiceSignatureFixtures(t *testing.T) {
	f := must.Value(os.Open(filepath.Join("testdata", "fixtures", "nmap", "services.xml")))
	defer f.Close()
	res := must.Value(scan.Parse(f))
	byPort := map[uint16]model.ServiceObs{}
	for i, s := range res.Services {
		s.ID = int64(i + 1)
		byPort[s.Key.Port] = s
	}
	fetch := &fakeFetcher{}
	e := NewEngine(builtins(t), fetch)
	tests := []struct {
		port uint16
		want []wantDet
	}{
		{21, []wantDet{{id: "ftp", severity: model.SevLow}, {id: "vsftpd", severity: model.SevLow, version: "3.0.3"}}},
		{2121, []wantDet{{id: "ftp", severity: model.SevLow}, {id: "vsftpd", severity: model.SevHigh, version: "2.3.4", outdated: true}}},
		{3306, []wantDet{{id: "mysql", severity: model.SevHigh, version: "5.7.44", outdated: true}}},
		{3307, []wantDet{{id: "mysql", severity: model.SevMedium}}},
		{5673, []wantDet{{id: "rabbitmq-amqp", severity: model.SevLow, version: "3.12.12"}}},
		{6379, []wantDet{{id: "redis", severity: model.SevLow, version: "7.2.4"}, {id: "redis-noauth", severity: model.SevHigh, version: "7.2.4"}}},
		{6380, []wantDet{{id: "redis", severity: model.SevLow}}},
		{6381, []wantDet{{id: "redis", severity: model.SevLow}}},
		{15432, []wantDet{{id: "postgresql", severity: model.SevMedium}}}, // "9.6.0 or later": no version
	}
	for _, tt := range tests {
		t.Run(strconv.Itoa(int(tt.port)), func(t *testing.T) {
			s, ok := byPort[tt.port]
			if !assert.True(t, ok, "port %d not in fixture", tt.port) {
				return
			}

			checkDetections(t, match(e, s, model.HTTPObs{}), tt.want)
		})
	}
	assert.Len(t, 0, fetch.Calls())
}

func TestPostgresVersionBound(t *testing.T) {
	e := NewEngine(builtins(t), &fakeFetcher{})
	for version, want := range map[string]string{"9.6.0 or later": "", "16.0 - 16.2": "16.0", "16.4": "16.4"} {
		s := model.ServiceObs{ID: 1, Key: model.AssetKey{IP: netip.MustParseAddr("127.0.0.1"), Port: 5432, Proto: "tcp"},
			Product: "PostgreSQL DB", Version: version, Banner: "postgresql"}
		var got *model.Detection
		for _, d := range match(e, s, model.HTTPObs{}) {
			if d.SignatureID == "postgresql" {
				got = &d
			}
		}
		if !assert.NotNil(t, got, "%q: postgresql not detected", version) {
			continue
		}
		assert.Equal(t, want, got.Evidence["version"], version)
	}
}
