package sig

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"net/http"
	"net/netip"
	"os"
	"sort"
	"testing"
	"time"

	"github.com/ctx42/testing/pkg/assert"

	"github.com/chrobson/ramparteye/internal/model"
)

var update = flag.Bool("update", false, "rewrite golden files")

type scenario struct {
	name  string
	svc   model.ServiceObs
	obs   model.HTTPObs
	paths map[string]ProbeResponse
}

func scenarios() []scenario {
	expired := &model.TLSInfo{Subject: "CN=old.lab", SelfSigned: true, Expired: true, NotAfter: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC), SANs: []string{"staging.lab.test"}}
	return []scenario{
		{name: "wordpress", svc: svc(80, ""), obs: func() model.HTTPObs {
			o := httpObs(80, "Blog", `<meta name="generator" content="WordPress 6.4.2" /><link href="/wp-content/themes/x.css">`,
				map[string][]string{"Server": {"Apache/2.4.57 (Debian)"}, "X-Powered-By": {"PHP/8.2.7"}})
			o.Cookies = []model.Cookie{{Name: "wordpress_test_cookie"}}
			return o
		}()},
		{name: "drupal-nginx", svc: svc(8081, ""), obs: httpObs(8081, "Home | Site", `<div data-drupal-selector="x">`,
			map[string][]string{"Server": {"nginx/1.25.3"}, "X-Generator": {"Drupal 10 (https://www.drupal.org)"}})},
		{name: "joomla", svc: svc(8082, ""), obs: httpObs(8082, "Home", `<meta name="generator" content="Joomla! - Open Source Content Management" />`, nil)},
		{name: "tomcat-manager", svc: svc(8080, ""), obs: httpObs(8080, "Apache Tomcat/9.0.83", "<h3>Apache Tomcat/9.0.83</h3>", nil),
			paths: map[string]ProbeResponse{"GET /manager/html": {Status: 401, Header: http.Header{"Www-Authenticate": {`Basic realm="Tomcat Manager Application"`}}}}},
		{name: "jenkins", svc: svc(8083, ""), obs: func() model.HTTPObs {
			o := httpObs(8083, "Sign in [Jenkins]", "", map[string][]string{"X-Jenkins": {"2.426.1"}, "X-Hudson": {"1.395"}})
			o.Redirects = []model.Redirect{{URL: "http://10.20.1.5:8083/", Status: 403}}
			return o
		}()},
		{name: "grafana-via-api", svc: svc(3000, ""), obs: httpObs(3000, "", "", nil),
			paths: map[string]ProbeResponse{"GET /api/health": {Status: 200, Body: []byte(`{"commit":"abc","database":"ok","version":"10.2.3"}`)}}},
		{name: "gitlab", svc: svc(8084, ""), obs: func() model.HTTPObs {
			o := httpObs(8084, "Sign in · GitLab", "", nil)
			o.Cookies = []model.Cookie{{Name: "_gitlab_session", HTTPOnly: true}}
			return o
		}()},
		{name: "phpmyadmin", svc: svc(8085, ""), obs: func() model.HTTPObs {
			o := httpObs(8085, "phpMyAdmin", `<input type="password" name="pma_password">`, nil)
			o.Cookies = []model.Cookie{{Name: "phpMyAdmin", HTTPOnly: true}}
			return o
		}()},
		{name: "kibana", svc: svc(5601, ""), obs: httpObs(5601, "Elastic", "", map[string][]string{"Kbn-Name": {"kibana"}, "Kbn-Version": {"8.11.1"}})},
		{name: "iis-admin", svc: svc(8086, ""), obs: httpObs(8086, "IIS Windows Server", "", map[string][]string{"Server": {"Microsoft-IIS/10.0"}, "X-Powered-By": {"ASP.NET"}}),
			paths: map[string]ProbeResponse{"GET /admin": {Status: 401}}},
		{name: "spring-actuator", svc: svc(8087, ""), obs: httpObs(8087, "", "", nil),
			paths: map[string]ProbeResponse{"GET /actuator": {Status: 200, Body: []byte(`{"_links":{"self":{"href":"/actuator"}}}`)}}},
		{name: "apache-server-status", svc: svc(8088, ""), obs: httpObs(8088, "", "", map[string][]string{"Server": {"Apache"}}),
			paths: map[string]ProbeResponse{"GET /server-status": {Status: 200, Body: []byte(`<h1>Apache Server Status for 10.20.1.5</h1><dt>Server Version: Apache/2.4.58 (Unix)</dt>`)}}},
		{name: "login-path", svc: svc(8089, ""), obs: httpObs(8089, "Welcome", "<p>hi</p>", nil),
			paths: map[string]ProbeResponse{"GET /login": {Status: 200, Body: []byte(`<form><input type='password' name=p></form>`)}}},
		{name: "staging-expired-tls", svc: svc(443, ""), obs: func() model.HTTPObs {
			o := httpObs(443, "Shop - Staging", "", map[string][]string{"Server": {"nginx"}})
			o.URL = "https://10.20.1.5/"
			o.TLS = expired
			return o
		}()},
		{name: "dev-vhost", svc: svc(8090, "dev.lab.test"), obs: httpObs(8090, "App", "", nil)},
		{name: "mosquitto", svc: func() model.ServiceObs {
			s := svc(1883, "")
			s.Product = "Mosquitto version 2.0.18"
			return s
		}(), obs: model.HTTPObs{}},
		{name: "iot-camera", svc: svc(8091, ""), obs: httpObs(8091, "Network Video Recorder Login", "", map[string][]string{"Server": {"GoAhead-Webs"}})},
		{name: "plain-nothing", svc: svc(8092, ""), obs: httpObs(8092, "It works", "<p>static</p>", map[string][]string{"Server": {"Caddy"}})},
		// Gitea's sign-in form on its home page: the product explains the
		// password field, so no generic login-page next to it.
		{name: "gitea-login", svc: svc(3001, ""), obs: httpObs(3001, "Gitea: Git with a cup of tea",
			`<form><input type="password" name="password"></form><footer>Powered by Gitea</footer>`, nil)},
		// nginx names only the server: the login form stays reported.
		{name: "nginx-login", svc: svc(8094, ""), obs: httpObs(8094, "Sign in",
			`<form><input type="password" name="pw"></form>`, map[string][]string{"Server": {"nginx/1.25.3"}})},
		// go-httpbin (Go port of httpbin) names itself only in the title.
		{name: "go-httpbin", svc: svc(8888, ""), obs: httpObs(8888, "go-httpbin(1): HTTP Client Testing Service", "<h1>go-httpbin(1)</h1>", nil)},
		{name: "favicon-and-dirlisting", svc: svc(8093, ""), obs: httpObs(8093, "Index of /", "<h1>Index of /</h1>", nil)},
	}
}

type goldenDet struct {
	Signature  string            `json:"signature"`
	Category   string            `json:"category"`
	Confidence int               `json:"confidence"`
	Evidence   map[string]string `json:"evidence"`
}

// The golden file is the prototype's output: the port must detect exactly
// what the prototype detected.
func TestBuiltinGoldenDetections(t *testing.T) {
	sigs := builtins(t)
	got := map[string][]goldenDet{}
	for _, sc := range scenarios() {
		f := &fakeFetcher{resp: sc.paths}
		e := NewEngine(sigs, f)

		ds := match(e, sc.svc, sc.obs)

		out := []goldenDet{}
		for _, d := range ds {
			assert.Equal(t, sc.svc.ID, d.ServiceID, sc.name)
			out = append(out, goldenDet{d.SignatureID, d.Category, d.Confidence, d.Evidence})
		}
		sort.Slice(out, func(i, j int) bool { return out[i].Signature < out[j].Signature })
		got[sc.name] = out
		assert.True(t, len(f.Calls()) <= 12, "%s: %d path probes", sc.name, len(f.Calls()))
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	assert.NoError(t, enc.Encode(got))
	const golden = "testdata/golden/detections.json"
	if *update {
		assert.NoError(t, os.WriteFile(golden, buf.Bytes(), 0o644))
	}
	want, err := os.ReadFile(golden)
	assert.NoError(t, err)
	assert.Equal(t, string(want), buf.String())
}

func TestShortCircuitAvoidsProbes(t *testing.T) {
	and := mustParse(t, `id: and-sig
name: A
category: other
confidence: 50
condition: and
matchers:
  - {type: path, path: /x, status: [200]}
  - {type: header, name: X-Never}
`)
	or := mustParse(t, `id: or-sig
name: O
category: other
confidence: 50
matchers:
  - {type: path, path: /y, status: [200]}
  - {type: title, regex: Hello}
`)
	f := &fakeFetcher{}
	e := NewEngine([]*Signature{and, or}, f)

	ds := match(e, svc(80, ""), httpObs(80, "Hello", "", nil))

	assert.Len(t, 1, ds)
	assert.Equal(t, "or-sig", ds[0].SignatureID)
	assert.Len(t, 0, f.Calls())
}

func TestPathProbesAreCachedAndSkippedWithoutHTTP(t *testing.T) {
	a := mustParse(t, "id: a1\nname: A\ncategory: other\nconfidence: 5\nmatchers:\n  - {type: path, path: /admin, status: [200]}\n")
	b := mustParse(t, "id: b1\nname: B\ncategory: other\nconfidence: 5\nmatchers:\n  - {type: path, path: /admin, regex: secret}\n")
	f := &fakeFetcher{resp: map[string]ProbeResponse{"GET /admin": {Status: 200, Body: []byte("secret")}}}
	e := NewEngine([]*Signature{a, b}, f)

	assert.Len(t, 2, match(e, svc(80, ""), httpObs(80, "", "", nil)))
	assert.Equal(t, []string{"GET /admin"}, f.Calls())

	f.calls = nil
	assert.Len(t, 0, match(e, svc(22, ""), model.HTTPObs{}))
	assert.Len(t, 0, f.Calls())

	// No fetcher: path matchers never match.
	assert.Len(t, 0, match(NewEngine([]*Signature{a}, nil), svc(80, ""), httpObs(80, "", "", nil)))
}

func TestProbeGateRefusesPathProbes(t *testing.T) {
	a := mustParse(t, "id: a1\nname: A\ncategory: other\nconfidence: 5\nmatchers:\n  - {type: path, path: /admin, status: [200]}\n")
	b := mustParse(t, "id: b1\nname: B\ncategory: other\nconfidence: 5\nmatchers:\n  - {type: path, path: /other, status: [200]}\n")
	f := &fakeFetcher{resp: map[string]ProbeResponse{"GET /admin": {Status: 200}, "GET /other": {Status: 200}}}
	var asked []netip.Addr
	e := NewEngine([]*Signature{a, b}, f)
	e.ProbeGate = func(host netip.Addr) bool {
		asked = append(asked, host)
		return len(asked) == 1 // budget: one probe
	}

	ds := match(e, svc(80, ""), httpObs(80, "", "", nil))

	assert.Len(t, 1, ds)
	assert.Equal(t, "a1", ds[0].SignatureID)
	assert.Equal(t, []string{"GET /admin"}, f.Calls())
	assert.Equal(t, []netip.Addr{netip.MustParseAddr("10.20.1.5"), netip.MustParseAddr("10.20.1.5")}, asked)
}

func TestProbeGateNotAskedForCachedProbe(t *testing.T) {
	a := mustParse(t, "id: a1\nname: A\ncategory: other\nconfidence: 5\nmatchers:\n  - {type: path, path: /admin, status: [200]}\n")
	b := mustParse(t, "id: b1\nname: B\ncategory: other\nconfidence: 5\nmatchers:\n  - {type: path, path: /admin, regex: x}\n")
	f := &fakeFetcher{resp: map[string]ProbeResponse{"GET /admin": {Status: 200, Body: []byte("x")}}}
	n := 0
	e := NewEngine([]*Signature{a, b}, f)
	e.ProbeGate = func(netip.Addr) bool { n++; return true }

	assert.Len(t, 2, match(e, svc(80, ""), httpObs(80, "", "", nil)))
	assert.Equal(t, 1, n)
}

func TestMatchStopsProbingWhenContextDone(t *testing.T) {
	a := mustParse(t, "id: a1\nname: A\ncategory: other\nconfidence: 5\nmatchers:\n  - {type: path, path: /admin, status: [200]}\n")
	f := &fakeFetcher{resp: map[string]ProbeResponse{"GET /admin": {Status: 200}}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	ds := NewEngine([]*Signature{a}, f).Match(ctx, svc(80, ""), httpObs(80, "", "", nil))

	assert.Len(t, 0, ds)
	assert.Len(t, 0, f.Calls())
}

func TestFaviconAndVersionEvidence(t *testing.T) {
	s := mustParse(t, `id: fav
name: F
category: other
confidence: 70
condition: and
matchers:
  - {type: favicon, hashes: [-123, 456]}
  - {type: header, name: Server, regex: 'Srv/(?P<version>[0-9.]+)'}
`)
	h := int32(-123)
	o := httpObs(80, "", "", map[string][]string{"Server": {"Srv/1.2.3 extra"}})
	o.FaviconMMH3 = &h

	ds := match(NewEngine([]*Signature{s}, nil), svc(80, ""), o)

	assert.Len(t, 1, ds)
	want := map[string]string{"favicon_mmh3": "-123", "header:Server": "Srv/1.2.3", "version": "1.2.3"}
	assert.Equal(t, want, ds[0].Evidence)
}

func TestEvidenceIsClipped(t *testing.T) {
	s := mustParse(t, "id: long\nname: L\ncategory: other\nconfidence: 5\nmatchers:\n  - {type: title, regex: 'a+'}\n")
	title := string(bytes.Repeat([]byte("a"), 500))

	ds := match(NewEngine([]*Signature{s}, nil), svc(80, ""), httpObs(80, title, "", nil))

	assert.Len(t, 1, ds)
	assert.Len(t, 200, ds[0].Evidence["title"])
}

func TestSetSignatures(t *testing.T) {
	a := mustParse(t, "id: a1\nname: A\ncategory: other\nconfidence: 5\nmatchers:\n  - {type: title, regex: x}\n")
	e := NewEngine(nil, nil)
	assert.Len(t, 0, match(e, svc(80, ""), httpObs(80, "x", "", nil)))

	e.SetSignatures([]*Signature{a})

	assert.Len(t, 1, e.Signatures())
	assert.Len(t, 1, match(e, svc(80, ""), httpObs(80, "x", "", nil)))
}

func TestSuppressGeneric(t *testing.T) {
	det := func(id, cat string) model.Detection { return model.Detection{SignatureID: id, Category: cat} }
	ids := func(ds []model.Detection) []string {
		var out []string
		for _, d := range ds {
			out = append(out, d.SignatureID)
		}
		return out
	}
	tests := []struct {
		testN string

		in   []model.Detection
		want []string
	}{
		{"product other", []model.Detection{det("gitea", "other"), det("login-page", "admin-panel")}, []string{"gitea"}},
		{"product cms", []model.Detection{det("login-page", "admin-panel"), det("wordpress", "cms")}, []string{"wordpress"}},
		{"product panel", []model.Detection{det("jenkins", "admin-panel"), det("admin-panel", "admin-panel"), det("login-page", "admin-panel")}, []string{"jenkins"}},
		{"iot device", []model.Detection{det("iot-webui", "iot"), det("login-page", "admin-panel")}, []string{"iot-webui"}},
		{"server only", []model.Detection{det("nginx", "server"), det("login-page", "admin-panel")}, []string{"nginx", "login-page"}},
		{"framework only", []model.Detection{det("php", "framework"), det("admin-panel", "admin-panel")}, []string{"php", "admin-panel"}},
		{"tls property", []model.Detection{det("tls-self-signed", "other"), det("login-page", "admin-panel")}, []string{"tls-self-signed", "login-page"}},
		{"staging", []model.Detection{det("staging-env", "staging"), det("login-page", "admin-panel")}, []string{"staging-env", "login-page"}},
		{"custom product", []model.Detection{det("my-app", "other"), det("login-page", "admin-panel")}, []string{"my-app"}},
	}
	for _, tt := range tests {
		t.Run(tt.testN, func(t *testing.T) {
			have := ids(SuppressGeneric(tt.in))

			assert.Equal(t, tt.want, have)
		})
	}
}
