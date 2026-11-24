package safety

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/ctx42/testing/pkg/assert"
	"github.com/ctx42/testing/pkg/must"

	"github.com/chrobson/ramparteye/internal/scan"
)

type allowPrefix struct{ p netip.Prefix }

func (a allowPrefix) Allows(ip netip.Addr) bool { return a.p.Contains(ip) }
func (a allowPrefix) CheckPrefix(q netip.Prefix) error {
	if a.p.Bits() <= q.Bits() && a.p.Contains(q.Addr()) {
		return nil
	}
	return errNotInScope
}

var errNotInScope = errors.New("outside")

func pfx(s string) netip.Prefix { return netip.MustParsePrefix(s) }

func checkByName(t *testing.T, rep Report, name string) Check {
	t.Helper()
	for _, c := range rep.Checks {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("check %q missing in %+v", name, rep.Checks)
	return Check{}
}

func TestTransportCountsPerContext(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	c := &http.Client{Transport: Transport(http.DefaultTransport)}
	m := NewMeter()
	ctx := WithMeter(context.Background(), m)
	for _, method := range []string{"GET", "HEAD", "GET", "OPTIONS"} {
		req := must.Value(http.NewRequestWithContext(ctx, method, srv.URL, nil))
		if method == "OPTIONS" {
			req.Header.Set("Cookie", "a=b")
		}
		resp := must.Value(c.Do(req))
		_ = resp.Body.Close()
	}
	// Without a meter nothing is recorded and nothing breaks.
	req := must.Value(http.NewRequest("GET", srv.URL, nil))
	resp := must.Value(c.Do(req))
	_ = resp.Body.Close()

	r := m.Receipt(nil)
	assert.Equal(t, int64(2), r.HTTPGet)
	assert.Equal(t, int64(1), r.HTTPHead)
	assert.Equal(t, int64(1), r.HTTPOther)
	assert.Equal(t, int64(1), r.HTTPAuth)
	assert.Equal(t, 4.0, r.HTTPPeakRPS)
}

func TestFromWithoutMeter(t *testing.T) {
	assert.Nil(t, From(context.Background()))
	assert.Nil(t, From(nil)) //nolint:staticcheck
	assert.Equal(t, context.Background(), WithMeter(context.Background(), nil))
}

func TestSlidingWindowPeak(t *testing.T) {
	m := NewMeter()
	now := time.Unix(1000, 0)
	m.now = func() time.Time { return now }
	req := must.Value(http.NewRequest("GET", "http://x/", nil))
	for i := 0; i < 30; i++ { // 10 per second for 3 s
		m.CountHTTP(req)
		now = now.Add(100 * time.Millisecond)
	}
	assert.Equal(t, 10.0, m.Receipt(nil).HTTPPeakRPS)
}

func TestNmapAggregationAndChecks(t *testing.T) {
	m := NewMeter()
	t0 := time.Unix(0, 0)
	// Two parallel workers of 4 s each overlapping by 2 s: busy 6 s.
	m.AddNmap(Invocation{Argv: []string{"-sn", "10.20.0.0/24"}, Packets: 1200, Raw: true, Elapsed: 4 * time.Second,
		Start: t0, End: t0.Add(4 * time.Second), Targets: []netip.Prefix{pfx("10.20.0.0/24")}})
	m.AddNmap(Invocation{Argv: []string{"-sn", "10.20.1.0/24"}, Packets: 600, Elapsed: 4 * time.Second,
		Start: t0.Add(2 * time.Second), End: t0.Add(6 * time.Second), Targets: []netip.Prefix{pfx("10.20.1.0/24")}})
	r := m.Receipt(allowPrefix{pfx("10.20.0.0/18")})

	assert.Equal(t, int64(6000), r.NmapBusyMs)
	assert.Equal(t, int64(1800), r.NmapPackets)
	assert.Equal(t, 1, r.NmapRawReported)
	assert.Equal(t, 2, r.NmapInvocations)
	assert.Equal(t, 300.0, r.EffectivePPS())
	assert.Equal(t, 300.0, r.NmapPeakInvPPS)
	assert.Equal(t, int64(512), r.TargetsChecked)
	assert.Equal(t, int64(0), r.TargetsOutsideAllowlist)
	assert.Len(t, 64, r.ArgvSHA256)
	assert.Len(t, 2, r.ArgvSample)

	r.ConfiguredMaxRate, r.HTTPRateLimit, r.HTTPBurst = 1000, 20, 5
	rep := BuildReport(r)
	assert.True(t, rep.OK)
	names := make([]string, 0, 5)
	for _, c := range rep.Checks {
		names = append(names, c.Name)
		assert.True(t, c.OK)
		assert.NotEmpty(t, c.Measured)
	}
	assert.Equal(t, []string{"scope respected", "rate within budget", "GET/HEAD only",
		"time window respected", "path probe budget"}, names)

	r.ConfiguredMaxRate = 200
	rep = BuildReport(r)
	assert.False(t, rep.OK)
	assert.False(t, checkByName(t, rep, "rate within budget").OK)
}

func TestRatePolicyLimit(t *testing.T) {
	r := Receipt{NmapPackets: 3000, NmapBusyMs: 1000, ConfiguredMaxRate: 5000, PolicyPPS: 2000}
	rep := BuildReport(r)
	assert.False(t, checkByName(t, rep, "rate within budget").OK)
	r.PolicyPPS = 4000
	assert.True(t, checkByName(t, BuildReport(r), "rate within budget").OK)
}

func TestRateHTTPPeak(t *testing.T) {
	r := Receipt{HTTPRateLimit: 20, HTTPBurst: 5, HTTPPeakRPS: 26}
	assert.False(t, checkByName(t, BuildReport(r), "rate within budget").OK)
	r.HTTPPeakRPS = 25
	assert.True(t, checkByName(t, BuildReport(r), "rate within budget").OK)
}

func TestReceiptFailsOnPost(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	c := &http.Client{Transport: Transport(nil)}
	m := NewMeter()
	ctx := WithMeter(context.Background(), m)
	for _, method := range []string{"GET", "HEAD", "POST"} {
		req := must.Value(http.NewRequestWithContext(ctx, method, srv.URL, nil))
		resp := must.Value(c.Do(req))
		_ = resp.Body.Close()
	}

	rep := BuildReport(m.Receipt(nil))

	got := checkByName(t, rep, "GET/HEAD only")
	assert.False(t, got.OK)
	assert.Contain(t, "other 1", got.Detail)
	assert.False(t, rep.OK)
	assert.Equal(t, map[string]int{"GET": 1, "HEAD": 1, "POST": 1}, m.Snapshot().Methods)
}

func TestScopeCheck(t *testing.T) {
	m := NewMeter()
	t0 := time.Unix(0, 0)
	m.AddNmap(Invocation{Argv: []string{"x"}, Start: t0, End: t0.Add(time.Second),
		Targets: []netip.Prefix{pfx("10.20.0.0/24"), pfx("192.168.1.7/32")}})
	r := m.Receipt(allowPrefix{pfx("10.20.0.0/16")})
	assert.Equal(t, int64(257), r.TargetsChecked)
	assert.Equal(t, int64(1), r.TargetsOutsideAllowlist)
	assert.False(t, checkByName(t, BuildReport(r), "scope respected").OK)
}

func TestWindowContains(t *testing.T) {
	loc := time.UTC
	at := func(h, mi int) time.Time { return time.Date(2026, 1, 5, h, mi, 0, 0, loc) }
	day := Window{Start: 9 * time.Hour, End: 17 * time.Hour, Loc: loc}
	assert.True(t, day.Contains(at(9, 0)))
	assert.True(t, day.Contains(at(12, 0)))
	assert.False(t, day.Contains(at(17, 1)))
	assert.False(t, day.Contains(at(3, 0)))

	night := Window{Start: 22 * time.Hour, End: 6 * time.Hour, Loc: loc}
	assert.True(t, night.Contains(at(23, 0)))
	assert.True(t, night.Contains(at(2, 0)))
	assert.False(t, night.Contains(at(12, 0)))
	assert.Equal(t, "22:00-06:00", night.String())
}

func TestTimeWindowCheck(t *testing.T) {
	m := NewMeter()
	now := time.Date(2026, 1, 5, 12, 0, 0, 0, time.UTC)
	m.now = func() time.Time { return now }
	m.SetWindow(Window{Start: 22 * time.Hour, End: 6 * time.Hour, Loc: time.UTC})
	m.AddNmap(Invocation{Argv: []string{"x"}, Start: now.Add(-time.Hour), End: now.Add(-time.Minute)})
	req := must.Value(http.NewRequest("GET", "http://x/", nil))
	m.CountHTTP(req)
	m.AddNmap(Invocation{Argv: []string{"y"},
		Start: time.Date(2026, 1, 5, 23, 0, 0, 0, time.UTC), End: time.Date(2026, 1, 5, 23, 5, 0, 0, time.UTC)})

	r := m.Receipt(nil)
	assert.Equal(t, int64(2), r.OutsideWindow) // the first run and the request
	assert.Equal(t, "22:00-06:00", r.TimeWindow)
	got := checkByName(t, BuildReport(r), "time window respected")
	assert.False(t, got.OK)

	r.OutsideWindow = 0
	assert.True(t, checkByName(t, BuildReport(r), "time window respected").OK)
}

func TestTimeWindowUnset(t *testing.T) {
	got := checkByName(t, BuildReport(NewMeter().Receipt(nil)), "time window respected")
	assert.True(t, got.OK)
	assert.Contain(t, "no window", got.Detail)
}

func TestPathProbeBudget(t *testing.T) {
	m := NewMeter()
	m.SetBudget(Budget{PathProbesPerHost: 2})
	a, b := netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2")

	assert.True(t, m.ProbeGate(a))
	assert.True(t, m.ProbeGate(a))
	assert.False(t, m.ProbeGate(a)) // third probe for a host with budget 2
	assert.True(t, m.ProbeGate(b))  // budgets are per host
	assert.True(t, m.ProbeGate(netip.MustParseAddr("::ffff:10.0.0.2")))
	assert.False(t, m.ProbeGate(b))

	r := m.Receipt(nil)
	assert.Equal(t, int64(4), r.PathProbes)
	assert.Equal(t, int64(2), r.PathProbesRefused)
	assert.Equal(t, 2, r.PathProbesMaxHost)
	assert.Equal(t, 2, r.PathProbeBudget)
	got := checkByName(t, BuildReport(r), "path probe budget")
	assert.True(t, got.OK) // refusing is the budget working
	assert.Contain(t, "2 refused", got.Detail)

	r.PathProbesMaxHost = 3 // a host got more than its budget
	assert.False(t, checkByName(t, BuildReport(r), "path probe budget").OK)
}

func TestPathProbeNoBudgetAllowsAll(t *testing.T) {
	m := NewMeter()
	a := netip.MustParseAddr("10.0.0.1")
	for i := 0; i < 50; i++ {
		assert.True(t, m.ProbeGate(a))
	}
	var nilMeter *Meter
	assert.True(t, nilMeter.ProbeGate(a))
}

func TestSnapshotLive(t *testing.T) {
	m := NewMeter()
	t0 := time.Unix(0, 0)
	m.AddNmap(Invocation{Argv: []string{"x"}, Packets: 500, Elapsed: 2 * time.Second,
		Start: t0, End: t0.Add(2 * time.Second)})
	req := must.Value(http.NewRequest("GET", "http://x/", nil))
	m.CountHTTP(req)

	s := m.Snapshot()

	assert.Equal(t, int64(500), s.Packets)
	assert.Equal(t, 250.0, s.PPS)
	assert.Equal(t, int64(1), s.HTTPRequests)
	assert.Equal(t, map[string]int{"GET": 1}, s.Methods)
	var nilMeter *Meter
	assert.Equal(t, Snapshot{}, nilMeter.Snapshot())
}

func TestConcurrentUse(t *testing.T) {
	m := NewMeter()
	m.SetBudget(Budget{PathProbesPerHost: 10})
	req := must.Value(http.NewRequest("GET", "http://x/", nil))
	host := netip.MustParseAddr("10.0.0.1")
	var wg sync.WaitGroup
	var mu sync.Mutex
	allowed := 0
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				m.CountHTTP(req)
				if m.ProbeGate(host) {
					mu.Lock()
					allowed++
					mu.Unlock()
				}
				m.AddNmap(Invocation{Argv: []string{"x"}, Packets: 1, Start: time.Now(), End: time.Now().Add(time.Millisecond)})
				_ = m.Snapshot()
				_ = m.Receipt(nil)
			}
		}()
	}
	wg.Wait()

	r := m.Receipt(nil)
	assert.Equal(t, 10, allowed)
	assert.Equal(t, int64(400), r.HTTPGet)
	assert.Equal(t, int64(400), r.NmapPackets)
	assert.Equal(t, int64(390), r.PathProbesRefused)
}

// Invocation must stay convertible from scan.Run so the runner can feed the
// scanner's metering straight into the meter.
func TestInvocationFromScanRun(t *testing.T) {
	run := scan.Run{Argv: []string{"-sn"}, Targets: []netip.Prefix{pfx("10.0.0.0/30")}, Packets: 9, Raw: true,
		Elapsed: time.Second, Start: time.Unix(1, 0), End: time.Unix(2, 0)}
	m := NewMeter()
	m.AddNmap(Invocation(run))
	r := m.Receipt(allowPrefix{pfx("10.0.0.0/8")})
	assert.Equal(t, int64(9), r.NmapPackets)
	assert.Equal(t, int64(4), r.TargetsChecked)
}
