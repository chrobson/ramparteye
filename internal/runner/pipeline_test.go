package runner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ctx42/testing/pkg/assert"
	"github.com/ctx42/testing/pkg/must"

	"github.com/chrobson/ramparteye/internal/httpfp"
	"github.com/chrobson/ramparteye/internal/model"
	"github.com/chrobson/ramparteye/internal/scan"
	"github.com/chrobson/ramparteye/internal/scope"
	"github.com/chrobson/ramparteye/internal/sig"
	"github.com/chrobson/ramparteye/internal/store"
)

const headerSig = `id: test-nginx
name: nginx
category: server
confidence: 85
matchers:
  - type: header
    name: Server
    regex: '(?i)nginx'
`

const pathSig = `id: test-status
name: Status page
category: server
confidence: 90
matchers:
  - type: path
    path: /status
    status: [200]
    regex: 'all good'
`

// fakeFetcher answers every path probe with 200 "all good".
type fakeFetcher struct {
	mu    sync.Mutex
	calls int
}

func (f *fakeFetcher) Fetch(context.Context, model.ServiceObs, model.HTTPObs, sig.ProbeRequest) (sig.ProbeResponse, error) {
	f.mu.Lock()
	f.calls++
	f.mu.Unlock()
	return sig.ProbeResponse{Status: 200, Body: []byte("all good")}, nil
}

func engine(t *testing.T, f sig.Fetcher, yamls ...string) *sig.Engine {
	t.Helper()
	var sigs []*sig.Signature
	for _, y := range yamls {
		sigs = append(sigs, must.Value(sig.Parse([]byte(y))))
	}
	return sig.NewEngine(sigs, f)
}

// pipelineFixture scans 10.20.0.0/24 (one live host with http on port 80)
// with a prober answering 200 from nginx.
func pipelineFixture(t *testing.T, yamls ...string) (*fixture, *fakeFetcher) {
	t.Helper()
	f := setup(t, model.Target{Kind: model.TargetCIDR, Value: "10.20.0.0/24"})
	f.fp.obs = model.HTTPObs{URL: "http://10.20.0.10/", Status: 200, Title: "Welcome",
		Headers: map[string][]string{"Server": {"nginx/1.27.3"}}}
	ff := &fakeFetcher{}
	f.r.eng = engine(t, ff, yamls...)
	return f, ff
}

func TestPipelineFingerprintsMatchesAndDiffs(t *testing.T) {
	f, ff := pipelineFixture(t, headerSig, pathSig)
	runID := f.runNow(t)

	assert.Len(t, 1, f.fs.services)
	svc := f.fs.services[0]
	assert.Equal(t, 200, f.fs.httpObs[svc.ID].Status)
	var ids []string
	for _, d := range f.fs.detections[svc.ID] {
		assert.Equal(t, svc.ID, d.ServiceID)
		ids = append(ids, d.SignatureID)
	}
	// Without an *httpfp.HTTPProber path probes are disabled: the engine's
	// own fetcher is never used.
	assert.Equal(t, []string{"test-nginx"}, ids)
	assert.Equal(t, 0, ff.calls)
	assert.Equal(t, []int64{runID}, f.fs.applied)
	// The prober received the endpoint nmap reported.
	eps := f.fp.endpoints()
	assert.Len(t, 1, eps)
	assert.Equal(t, "http", eps[0].Scheme)
	assert.Equal(t, svc.Key, eps[0].Key)
}

// staticScanner reports fixed services; their hosts are live.
type staticScanner struct{ svcs []model.ServiceObs }

func (s staticScanner) Discover(_ context.Context, ps []netip.Prefix, _ scan.Opts) (scan.Result, error) {
	res := scan.Result{Runs: []scan.Run{run(ps)}}
	for _, sv := range s.svcs {
		for _, p := range ps {
			if p.Contains(sv.Key.IP) {
				res.Hosts = append(res.Hosts, model.HostObs{IP: sv.Key.IP, Up: true})
			}
		}
	}
	return res, nil
}

func (s staticScanner) Services(_ context.Context, hosts []netip.Addr, _ scan.Opts) (scan.Result, error) {
	res := scan.Result{}
	for _, sv := range s.svcs {
		if slices.Contains(hosts, sv.Key.IP) {
			res.Services = append(res.Services, sv)
		}
	}
	return res, nil
}

// realFixture scans 127.0.0.1 with a real scoped httpfp.HTTPProber against
// an httptest server whose /status page matches pathSig. hits counts
// requests to /status.
func realFixture(t *testing.T, yamls ...string) (*Runner, *fakeStore, *atomic.Int32) {
	t.Helper()
	hits := &atomic.Int32{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/status" {
			hits.Add(1)
			_, _ = w.Write([]byte("all good"))
			return
		}
		w.Header().Set("Server", "nginx/1.27.3")
		_, _ = w.Write([]byte("<title>Welcome</title>"))
	}))
	t.Cleanup(srv.Close)
	u := must.Value(url.Parse(srv.URL))
	port := must.Value(strconv.Atoi(u.Port()))
	ip := netip.MustParseAddr("127.0.0.1")

	sc := must.Value(scope.New([]netip.Prefix{pfx("127.0.0.0/8")}, nil, nil))
	fs := newFakeStore()
	fs.targets[1] = model.Target{ID: 1, Kind: model.TargetIP, Value: ip.String()}
	fs.configs = []store.ScanConfig{{ID: 1, Name: "local", TopPorts: 100, MaxRate: 1000, Workers: 1,
		Enabled: true, TargetIDs: []int64{1}}}
	scanner := staticScanner{svcs: []model.ServiceObs{{Key: model.AssetKey{IP: ip, Port: uint16(port), Proto: "tcp"},
		Product: "nginx", Banner: "http"}}}
	prober := httpfp.New(httpfp.Options{Scope: sc, SkipFavicon: true})
	r := New(fs, scanner, prober, engine(t, nil, yamls...), sc, Config{Log: quiet, RetryBackoff: time.Millisecond})
	return r, fs, hits
}

func runRealNow(t *testing.T, r *Runner) int64 {
	t.Helper()
	id := must.Value(r.Start(context.Background(), 1))
	r.Wait()
	return id
}

// With a real prober, signature path probes go through the run's prober:
// they reach the service and are counted in the run's safety receipt.
func TestPipelineRealProberPathProbe(t *testing.T) {
	r, fs, hits := realFixture(t, headerSig, pathSig)
	runID := runRealNow(t, r)

	assert.Equal(t, int32(1), hits.Load())
	var ids []string
	for _, ds := range fs.detections {
		for _, d := range ds {
			ids = append(ids, d.SignatureID)
		}
	}
	assert.Equal(t, []string{"test-nginx", "test-status"}, ids)
	rc := total(t, fs, runID)
	assert.Equal(t, int64(1), rc.PathProbes)
	assert.Equal(t, int64(1), rc.PathProbeWebServices)
	assert.True(t, rc.HTTPGet >= 2) // the page and the path probe, metered by the transport
	assert.Equal(t, int64(0), rc.HTTPOther)
}

// Domain targets resolving to the address are probed as virtual hosts;
// their detections belong to the address' service.
func TestPipelineProbesVirtualHosts(t *testing.T) {
	f, _ := pipelineFixture(t, headerSig)
	f.fs.targets[2] = model.Target{ID: 2, Kind: model.TargetDomain, Value: "app.lab.local"}
	f.fs.configs[0].TargetIDs = append(f.fs.configs[0].TargetIDs, 2)
	f.r.cfg.Resolver = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("10.20.0.10")}, nil
	}
	f.cfg = f.fs.configs[0]
	f.runNow(t)

	var vhosts []string
	for _, ep := range f.fp.endpoints() {
		vhosts = append(vhosts, ep.Key.VHost)
	}
	assert.Equal(t, []string{"", "app.lab.local"}, vhosts)
	for _, h := range f.fs.hosts {
		if h.IP == netip.MustParseAddr("10.20.0.10") {
			assert.Equal(t, "app.lab.local", h.Hostname)
		}
	}
	for id, ds := range f.fs.detections {
		for _, d := range ds {
			assert.Equal(t, id, d.ServiceID)
		}
	}
}

// Every endpoint probe has an overall deadline of 3 x the per-request
// timeout, so a host trickling bytes cannot hold the pipeline.
func TestPipelineProbeDeadline(t *testing.T) {
	f, _ := pipelineFixture(t, headerSig)
	f.fp.block = true
	f.fp.timeout = 20 * time.Millisecond
	start := time.Now()
	runID := f.runNow(t)
	assert.True(t, time.Since(start) < 2*time.Second)
	assert.Equal(t, "done", f.fs.runStatus(runID))
	for _, d := range f.fp.deadlines {
		assert.True(t, d <= 60*time.Millisecond)
		assert.True(t, d > 30*time.Millisecond)
	}
	assert.NotEmpty(t, f.fp.deadlines)
	assert.Len(t, 0, f.fs.httpObs) // nothing answered
}

func TestHTTPScheme(t *testing.T) {
	svc := func(port uint16, banner string) model.ServiceObs {
		return model.ServiceObs{Key: model.AssetKey{IP: netip.MustParseAddr("10.20.0.1"), Port: port, Proto: "tcp"}, Banner: banner}
	}
	cases := []struct {
		s    model.ServiceObs
		want string
	}{
		{svc(80, "http"), "http"},
		{svc(443, "http"), "https"},
		{svc(8443, "ssl/http"), "https"},
		{svc(8080, "http-proxy"), "http"},
		{svc(22, "ssh"), ""},
		{svc(8080, ""), "http"},
		{svc(9443, "tcpwrapped"), "https"},
		{svc(4444, "ssl/unknown"), "https"},
		{svc(4444, "unknown"), ""},
		{model.ServiceObs{Key: model.AssetKey{Port: 80, Proto: "udp"}, Banner: "http"}, ""},
	}
	for _, c := range cases {
		assert.Equal(t, c.want, HTTPScheme(c.s))
	}
}

func TestMergeDetectionsKeepsMostConfident(t *testing.T) {
	a := []model.Detection{{SignatureID: "x", Confidence: 50}}
	b := []model.Detection{{SignatureID: "x", Confidence: 90}, {SignatureID: "y", Confidence: 10}}
	got := mergeDetections(a, b)
	assert.Len(t, 2, got)
	assert.Equal(t, 90, got[0].Confidence)
}
