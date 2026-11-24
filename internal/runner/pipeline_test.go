package runner

import (
	"context"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/ctx42/testing/pkg/assert"
	"github.com/ctx42/testing/pkg/must"

	"github.com/chrobson/ramparteye/internal/model"
	"github.com/chrobson/ramparteye/internal/sig"
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
	assert.Equal(t, []string{"test-nginx", "test-status"}, ids)
	assert.Equal(t, 1, ff.calls)
	assert.Equal(t, []int64{runID}, f.fs.applied)
	// The prober received the endpoint nmap reported.
	eps := f.fp.endpoints()
	assert.Len(t, 1, eps)
	assert.Equal(t, "http", eps[0].Scheme)
	assert.Equal(t, svc.Key, eps[0].Key)
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
