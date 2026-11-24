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
		assert.Equal(t, StatusPass, c.Status)
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

func TestRateUnmeasuredWithoutRunTime(t *testing.T) {
	r := Receipt{NmapPackets: 500, ConfiguredMaxRate: 1000}

	rep := BuildReport(r)

	got := checkByName(t, rep, "rate within budget")
	assert.Equal(t, StatusUnmeasured, got.Status)
	assert.False(t, got.OK)
	assert.False(t, rep.OK)
}

func TestRateFallsBackToElapsed(t *testing.T) {
	r := Receipt{NmapPackets: 3000, NmapElapsedMs: 2000, ConfiguredMaxRate: 1000}
	got := checkByName(t, BuildReport(r), "rate within budget")
	assert.Equal(t, StatusFail, got.Status)

	r.ConfiguredMaxRate = 2000
	assert.Equal(t, StatusPass, checkByName(t, BuildReport(r), "rate within budget").Status)
}

func TestRateNothingSentPasses(t *testing.T) {
	got := checkByName(t, BuildReport(Receipt{}), "rate within budget")
	assert.Equal(t, StatusPass, got.Status)
}

func TestPeakInvocationAgainstBudget(t *testing.T) {
	m := NewMeter()
	t0 := time.Unix(0, 0)
	// A 100 ms burst of 2000 packets: dropped by the old 1 s minimum, now
	// divided by 1 s. The average over a long busy span stays low.
	m.AddNmap(Invocation{Argv: []string{"a"}, Packets: 2000, Elapsed: 100 * time.Millisecond,
		Start: t0, End: t0.Add(time.Minute)})
	m.SetBudget(Budget{RunPPS: 1000})

	r := m.Receipt(nil)

	assert.Equal(t, 2000.0, r.NmapPeakInvPPS)
	assert.True(t, r.EffectivePPS() < 1000)
	assert.Equal(t, StatusFail, checkByName(t, BuildReport(r), "rate within budget").Status)

	m.SetBudget(Budget{PolicyPPS: 1500})
	assert.Equal(t, StatusFail, checkByName(t, BuildReport(m.Receipt(nil)), "rate within budget").Status)
	m.SetBudget(Budget{RunPPS: 2000, PolicyPPS: 5000})
	assert.Equal(t, StatusPass, checkByName(t, BuildReport(m.Receipt(nil)), "rate within budget").Status)
}

func TestScopeUnmeasuredWithoutTargets(t *testing.T) {
	m := NewMeter()
	m.AddNmap(Invocation{Argv: []string{"x"}, Packets: 1, Start: time.Unix(0, 0), End: time.Unix(1, 0)})

	for _, allow := range []Allowlist{nil, allowPrefix{pfx("10.0.0.0/8")}} {
		got := checkByName(t, BuildReport(m.Receipt(allow)), "scope respected")
		assert.Equal(t, StatusUnmeasured, got.Status)
	}
	// Nothing scanned, nothing to re-check.
	assert.Equal(t, StatusPass, checkByName(t, BuildReport(NewMeter().Receipt(nil)), "scope respected").Status)
}

func TestPathProbeGateNeverConsulted(t *testing.T) {
	m := NewMeter()
	m.SetBudget(Budget{PathProbesPerHost: 2})
	m.SetPathSignatures(3)

	// No web services evaluated: the gate had nothing to do.
	got := checkByName(t, BuildReport(m.Receipt(nil)), "path probe budget")
	assert.Equal(t, StatusPass, got.Status)
	assert.Contain(t, "not applicable: no web services", got.Detail)

	m.AddWebServices(2)
	got = checkByName(t, BuildReport(m.Receipt(nil)), "path probe budget")
	assert.Equal(t, StatusUnmeasured, got.Status)

	m.ProbeGate(netip.MustParseAddr("10.0.0.1"))
	assert.Equal(t, StatusPass, checkByName(t, BuildReport(m.Receipt(nil)), "path probe budget").Status)

	// No path-probe signatures at all: nothing to measure, pass.
	assert.Equal(t, StatusPass, checkByName(t, BuildReport(NewMeter().Receipt(nil)), "path probe budget").Status)
}

func TestDrainReturnsDeltaOnce(t *testing.T) {
	m := NewMeter()
	t0 := time.Unix(0, 0)
	req := must.Value(http.NewRequest("GET", "http://x/", nil))
	m.AddNmap(Invocation{Argv: []string{"a"}, Packets: 100, Elapsed: 2 * time.Second,
		Start: t0, End: t0.Add(2 * time.Second), Targets: []netip.Prefix{pfx("10.0.0.1/32")}})
	m.CountHTTP(req)

	first := m.Drain(allowPrefix{pfx("10.0.0.0/8")})
	second := m.Drain(allowPrefix{pfx("10.0.0.0/8")})

	assert.Equal(t, int64(100), first.NmapPackets)
	assert.Equal(t, int64(1), first.HTTPGet)
	assert.Equal(t, int64(1), first.TargetsChecked)
	assert.Equal(t, 1, first.NmapInvocations)
	assert.Equal(t, int64(0), second.NmapPackets)
	assert.Equal(t, int64(0), second.HTTPGet)
	assert.Equal(t, int64(0), second.TargetsChecked)
	assert.Equal(t, 0, second.NmapInvocations)
	assert.Equal(t, "", second.ArgvSHA256)

	// The live view stays cumulative.
	m.AddNmap(Invocation{Argv: []string{"b"}, Packets: 50, Start: t0.Add(10 * time.Second), End: t0.Add(11 * time.Second)})
	s := m.Snapshot()
	assert.Equal(t, int64(150), s.Packets)
	assert.Equal(t, 1, s.Methods["GET"])
	assert.Equal(t, int64(50), m.Drain(nil).NmapPackets)
}

func TestDrainKeepsProbeBudget(t *testing.T) {
	m := NewMeter()
	m.SetBudget(Budget{PathProbesPerHost: 2})
	a := netip.MustParseAddr("10.0.0.1")
	assert.True(t, m.ProbeGate(a))
	first := m.Drain(nil)
	assert.True(t, m.ProbeGate(a))
	assert.False(t, m.ProbeGate(a)) // the first probe still counts after Drain
	second := m.Drain(nil)

	assert.Equal(t, map[string]int{"10.0.0.1": 1}, first.ProbeHosts)
	assert.Equal(t, map[string]int{"10.0.0.1": 1}, second.ProbeHosts)
	assert.Equal(t, 2, second.PathProbesMaxHost) // accumulated, not the delta
	assert.Equal(t, int64(1), second.PathProbesRefused)
}

func TestSeedProbesHoldsBudgetAcrossResume(t *testing.T) {
	m := NewMeter()
	m.SetBudget(Budget{PathProbesPerHost: 2})
	a, b := netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2")
	m.SeedProbes(map[netip.Addr]int{a: 2, b: 1})

	assert.False(t, m.ProbeGate(a))
	assert.True(t, m.ProbeGate(b))
	assert.False(t, m.ProbeGate(b))
	d := m.Drain(nil)
	assert.Equal(t, map[string]int{"10.0.0.2": 1}, d.ProbeHosts) // seeded counts are not re-saved
	assert.Equal(t, 2, d.PathProbesMaxHost)
}

type failingTransport struct{}

func (failingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("connection refused")
}

func TestTransportCountsFailedRequest(t *testing.T) {
	m := NewMeter()
	c := &http.Client{Transport: Transport(failingTransport{})}
	req := must.Value(http.NewRequestWithContext(WithMeter(context.Background(), m), "GET", "http://x.invalid/", nil))

	_, err := c.Do(req) //nolint:bodyclose
	assert.Error(t, err)

	assert.Equal(t, int64(1), m.Receipt(nil).HTTPGet)
}

func TestTransportCountsRedirectHop(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.Redirect(w, r, "/next", http.StatusFound)
		}
	}))
	defer srv.Close()
	m := NewMeter()
	c := &http.Client{Transport: Transport(nil)}
	req := must.Value(http.NewRequestWithContext(WithMeter(context.Background(), m), "GET", srv.URL, nil))

	resp := must.Value(c.Do(req))
	_ = resp.Body.Close()

	assert.Equal(t, int64(2), m.Receipt(nil).HTTPGet) // the 302 and the hop it led to
}

func TestReportStatus(t *testing.T) {
	ok := Receipt{}
	rep := BuildReport(ok)
	assert.Equal(t, ReportOK, rep.Status)
	assert.True(t, rep.OK)

	incomplete := Receipt{NmapPackets: 10} // sent packets, no run time
	rep = BuildReport(incomplete)
	assert.Equal(t, ReportIncomplete, rep.Status)
	assert.False(t, rep.OK)

	failed := Receipt{HTTPOther: 1}
	rep = BuildReport(failed)
	assert.Equal(t, ReportFailed, rep.Status)
	assert.False(t, rep.OK)

	both := Receipt{NmapPackets: 10, HTTPOther: 1} // a failure outranks unmeasured
	assert.Equal(t, ReportFailed, BuildReport(both).Status)
}

func TestScopeUncheckedInvocations(t *testing.T) {
	t0 := time.Unix(0, 0)
	m := NewMeter()
	m.AddNmap(Invocation{Argv: []string{"a"}, Start: t0, End: t0.Add(time.Second),
		Targets: []netip.Prefix{pfx("10.0.0.1/32")}})
	m.AddNmap(Invocation{Argv: []string{"b"}, Start: t0, End: t0.Add(time.Second)}) // no operands

	rep := BuildReport(m.Receipt(allowPrefix{pfx("10.0.0.0/8")}))

	got := checkByName(t, rep, "scope respected")
	assert.Equal(t, StatusUnmeasured, got.Status) // the run without targets was never checked
	assert.Equal(t, 1, rep.UncheckedInvocations)

	// An address outside the scope is a failure even when others are unchecked.
	m.AddNmap(Invocation{Argv: []string{"c"}, Targets: []netip.Prefix{pfx("192.168.0.1/32")}})
	got = checkByName(t, BuildReport(m.Receipt(allowPrefix{pfx("10.0.0.0/8")})), "scope respected")
	assert.Equal(t, StatusFail, got.Status)
}

func TestDrainNilAllowlistKeepsTargetsPending(t *testing.T) {
	allow := allowPrefix{pfx("10.0.0.0/8")}
	m := NewMeter()
	m.AddNmap(Invocation{Argv: []string{"a"}, Targets: []netip.Prefix{pfx("10.0.0.0/30")}})

	first := m.Drain(nil)

	assert.Equal(t, 1, first.UncheckedInvocations)
	assert.Equal(t, int64(0), first.TargetsChecked)
	assert.Equal(t, StatusUnmeasured, checkByName(t, BuildReport(first), "scope respected").Status)

	m.AddNmap(Invocation{Argv: []string{"b"}, Targets: []netip.Prefix{pfx("192.168.0.1/32")}})
	second := m.Drain(allow)

	assert.Equal(t, int64(5), second.TargetsChecked) // 4 pending + 1 new
	assert.Equal(t, int64(1), second.TargetsOutsideAllowlist)
	assert.Equal(t, -1, second.UncheckedInvocations) // the pending run is resolved
	assert.Equal(t, 0, first.UncheckedInvocations+second.UncheckedInvocations)

	m.AddNmap(Invocation{Argv: []string{"c"}, Targets: []netip.Prefix{pfx("10.0.1.1/32")}})
	third := m.Drain(allow)
	assert.Equal(t, int64(1), third.TargetsChecked) // pending was cleared
	assert.Equal(t, 0, third.UncheckedInvocations)
}

func TestRestoreAfterFailedSave(t *testing.T) {
	allow := allowPrefix{pfx("10.0.0.0/8")}
	m := NewMeter()
	m.SetBudget(Budget{PathProbesPerHost: 2})
	t0 := time.Unix(0, 0)
	req := must.Value(http.NewRequest("GET", "http://x/", nil))
	a := netip.MustParseAddr("10.0.0.1")
	m.AddNmap(Invocation{Argv: []string{"a"}, Packets: 100, Raw: true, Elapsed: 2 * time.Second,
		Start: t0, End: t0.Add(2 * time.Second), Targets: []netip.Prefix{pfx("10.0.0.1/32")}})
	m.CountHTTP(req)
	m.ProbeGate(a)
	m.AddWebServices(1)
	lost := m.Drain(allow)

	m.Restore(lost)
	m.AddNmap(Invocation{Argv: []string{"b"}, Packets: 50, Elapsed: time.Second,
		Start: t0.Add(5 * time.Second), End: t0.Add(6 * time.Second), Targets: []netip.Prefix{pfx("10.0.0.2/32")}})
	got := m.Drain(allow)

	assert.Equal(t, int64(150), got.NmapPackets)
	assert.Equal(t, 2, got.NmapInvocations)
	assert.Equal(t, 1, got.NmapRawReported)
	assert.Equal(t, int64(3000), got.NmapBusyMs) // 2 s restored + 1 s new
	assert.Equal(t, int64(2), got.TargetsChecked)
	assert.Equal(t, int64(1), got.HTTPGet)
	assert.Equal(t, int64(1), got.PathProbes)
	assert.Equal(t, int64(1), got.PathProbeGateCalls)
	assert.Equal(t, int64(1), got.PathProbeWebServices)
	assert.Equal(t, map[string]int{"10.0.0.1": 1}, got.ProbeHosts)
	assert.Equal(t, lost.ArgvSample[0], got.ArgvSample[0])
	// The probe still counts once against the budget.
	assert.True(t, m.ProbeGate(a))
	assert.False(t, m.ProbeGate(a))
}

func TestPathProbeSignatureCountUnknown(t *testing.T) {
	m := NewMeter()
	m.AddWebServices(3)

	got := checkByName(t, BuildReport(m.Receipt(nil)), "path probe budget")
	assert.Equal(t, StatusUnmeasured, got.Status)
	assert.Contain(t, "unknown", got.Detail)

	m.SetPathSignatures(0)
	got = checkByName(t, BuildReport(m.Receipt(nil)), "path probe budget")
	assert.Equal(t, StatusPass, got.Status)
	assert.Contain(t, "no path-probe signatures", got.Detail)

	m.SetPathSignatures(2)
	assert.Equal(t, StatusUnmeasured, checkByName(t, BuildReport(m.Receipt(nil)), "path probe budget").Status)
}

// A zone never makes a second host out of one address: the budget and the
// stored per-host counts use the bare address.
func TestProbeGateStripsZone(t *testing.T) {
	m := NewMeter()
	m.SetBudget(Budget{PathProbesPerHost: 1})

	assert.True(t, m.ProbeGate(netip.MustParseAddr("fe80::1%eth0")))
	assert.False(t, m.ProbeGate(netip.MustParseAddr("fe80::1")))
	assert.False(t, m.ProbeGate(netip.MustParseAddr("fe80::1%eth1")))
	assert.Equal(t, map[string]int{"fe80::1": 1}, m.Drain(nil).ProbeHosts)
}

func TestPathProbesDisabledRefusesAll(t *testing.T) {
	m := NewMeter()
	m.SetBudget(Budget{PathProbesPerHost: PathProbesDisabled})
	a := netip.MustParseAddr("10.0.0.1")

	assert.False(t, m.ProbeGate(a))
	assert.False(t, m.ProbeGate(a))

	r := m.Receipt(nil)
	assert.Equal(t, int64(0), r.PathProbes)
	assert.Equal(t, int64(2), r.PathProbesRefused)
	assert.Equal(t, PathProbesDisabled, r.PathProbeBudget)
	got := checkByName(t, BuildReport(r), "path probe budget")
	assert.True(t, got.OK)
	assert.Contain(t, "path probes disabled", got.Detail)

	r.PathProbes, r.PathProbesMaxHost = 1, 1 // a probe got through anyway
	assert.False(t, checkByName(t, BuildReport(r), "path probe budget").OK)
}
