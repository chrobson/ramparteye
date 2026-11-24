// Package safety measures what a scan run actually sent (nmap packets and
// elapsed time, HTTP requests per method, peak HTTP rate, path probes) and
// re-checks every scanned address against the scope. The result is a
// per-run safety receipt stored in run_safety, shown on the run page and
// served as JSON.
//
// The meter travels in the context: the runner attaches one per run, the HTTP
// transport records into it, and the runner feeds it the scanner's per-nmap
// metering (scan.Run converts to Invocation). Code that runs without a meter
// (tests, imports) records nothing. The package depends on no other
// RampartEye package, so the runner, scanner and signature engine can all
// use it.
package safety

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"hash"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// SampleArgv is how many nmap command lines are kept verbatim in the
// receipt (the hash covers all of them).
const SampleArgv = 4

// MinPeakElapsed is the smallest denominator of the per-invocation peak
// rate: --max-rate is an average, so a 10 ms run sending 5 packets says
// nothing about the cap. Shorter runs are divided by this instead of being
// dropped, so a burst cannot hide.
const MinPeakElapsed = time.Second

// Invocation is one nmap execution as measured by the scanner. Its fields
// match scan.Run exactly, so a scan.Run converts with Invocation(run).
type Invocation struct {
	Argv    []string       // full command line without the binary
	Targets []netip.Prefix // target operands of the command line
	Packets int64          // raw packets nmap reported, plus estimated connect() probes
	Raw     bool           // nmap printed its own packet counter for this run
	Elapsed time.Duration  // nmap's own elapsed time
	Start   time.Time
	End     time.Time
}

// Budget is the rate and probe budget a run is held to.
type Budget struct {
	RunPPS            int // packets/s budget of this run (its max rate); 0 = none
	PolicyPPS         int // instance-wide policy limit in packets/s; 0 = none
	PathProbesPerHost int // path probes allowed per host per run; <= 0 = unlimited
}

// Snapshot is the live view of a meter for the dashboard panel.
type Snapshot struct {
	Packets      int64          // packets of finished nmap invocations
	PPS          float64        // Packets over the time nmap was running
	HTTPRequests int64          // all outgoing HTTP requests
	Methods      map[string]int // requests per HTTP method
}

// acc holds what is reported by one Drain: everything measured since the
// previous Drain.
type acc struct {
	invocations int
	rawReported int
	packets     int64
	elapsed     time.Duration
	busy        []span // merged [start,end) intervals with nmap running
	peakInvPPS  float64
	argvHash    hash.Hash
	argvSample  []string
	targets     []netip.Prefix

	methods  map[string]int
	httpAuth int64
	peakRPS  int

	probes    map[netip.Addr]int
	refused   int64
	gateCalls int64
	webSvcs   int64
	outside   int64
}

func newAcc() acc {
	return acc{argvHash: sha256.New(), methods: map[string]int{}, probes: map[netip.Addr]int{}}
}

// Meter accumulates the measurements of one run. It is safe for concurrent
// use by workers and HTTP probes.
//
// Receipt peeks at the measurements since the last Drain; Drain returns them
// and starts over, so saving Drain output twice never counts anything twice.
// Snapshot is cumulative and unaffected by Drain.
type Meter struct {
	mu sync.Mutex

	cur acc

	// Cumulative state for Snapshot.
	totPackets int64
	totBusy    []span
	totMethods map[string]int

	window []time.Time // request times of the last second, kept across Drain

	budget   Budget
	base     map[netip.Addr]int // probes per host already drained or seeded
	pathSigs int

	tw    Window
	hasTW bool

	now func() time.Time
}

type span struct{ a, b time.Time }

// NewMeter returns an empty meter without budget or time window.
func NewMeter() *Meter {
	return &Meter{
		cur:        newAcc(),
		totMethods: map[string]int{},
		base:       map[netip.Addr]int{},
		now:        time.Now,
	}
}

type ctxKey struct{}

// WithMeter returns ctx carrying m.
func WithMeter(ctx context.Context, m *Meter) context.Context {
	if m == nil {
		return ctx
	}
	return context.WithValue(ctx, ctxKey{}, m)
}

// From returns the meter of ctx or nil.
func From(ctx context.Context) *Meter {
	if ctx == nil {
		return nil
	}
	m, _ := ctx.Value(ctxKey{}).(*Meter)
	return m
}

// SetBudget sets the budget the receipt is checked against.
func (m *Meter) SetBudget(b Budget) {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.budget = b
	m.mu.Unlock()
}

// SetWindow sets the time window nmap runs and HTTP requests must stay in.
func (m *Meter) SetWindow(w Window) {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.tw, m.hasTW = w, true
	m.mu.Unlock()
}

// SeedProbes loads the per-host path probe counts a resumed run already
// spent (see LoadProbes), so the budget holds across resumes. Seeded counts
// are not part of the next Drain.
func (m *Meter) SeedProbes(counts map[netip.Addr]int) {
	if m == nil {
		return
	}
	m.mu.Lock()
	for h, n := range counts {
		m.base[h.Unmap()] += n
	}
	m.mu.Unlock()
}

// SetPathSignatures records how many enabled signatures send path probes.
// If there are some and ProbeGate was never consulted, the "path probe
// budget" check is unmeasured rather than passed.
func (m *Meter) SetPathSignatures(n int) {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.pathSigs = n
	m.mu.Unlock()
}

// AddWebServices records n web services handed to the signature engine. With
// none, an unused probe gate is "not applicable" rather than unmeasured.
func (m *Meter) AddWebServices(n int) {
	if m == nil || n <= 0 {
		return
	}
	m.mu.Lock()
	m.cur.webSvcs += int64(n)
	m.mu.Unlock()
}

// AddNmap records one nmap invocation.
func (m *Meter) AddNmap(inv Invocation) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	c := &m.cur
	c.invocations++
	if inv.Raw {
		c.rawReported++
	}
	c.packets += inv.Packets
	m.totPackets += inv.Packets
	c.elapsed += inv.Elapsed
	if inv.End.After(inv.Start) {
		c.busy = mergeSpan(c.busy, span{inv.Start, inv.End})
		m.totBusy = mergeSpan(m.totBusy, span{inv.Start, inv.End})
	}
	if pps := float64(inv.Packets) / max(inv.Elapsed, MinPeakElapsed).Seconds(); pps > c.peakInvPPS {
		c.peakInvPPS = pps
	}
	if m.hasTW && !inv.Start.IsZero() && (!m.tw.Contains(inv.Start) || !m.tw.Contains(inv.End)) {
		c.outside++
	}
	line := strings.Join(inv.Argv, " ")
	c.argvHash.Write([]byte(line))
	c.argvHash.Write([]byte{'\n'})
	if len(c.argvSample) < SampleArgv {
		c.argvSample = append(c.argvSample, line)
	}
	c.targets = append(c.targets, inv.Targets...)
}

// mergeSpan inserts s into a sorted list of disjoint spans.
func mergeSpan(ss []span, s span) []span {
	out := make([]span, 0, len(ss)+1)
	placed := false
	for _, x := range ss {
		switch {
		case x.b.Before(s.a):
			out = append(out, x)
		case s.b.Before(x.a):
			if !placed {
				out = append(out, s)
				placed = true
			}
			out = append(out, x)
		default:
			if x.a.Before(s.a) {
				s.a = x.a
			}
			if x.b.After(s.b) {
				s.b = x.b
			}
		}
	}
	if !placed {
		out = append(out, s)
	}
	return out
}

// CountHTTP records one outgoing HTTP request.
func (m *Meter) CountHTTP(req *http.Request) {
	if m == nil || req == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	method := strings.ToUpper(req.Method)
	if method == "" {
		method = http.MethodGet
	}
	m.cur.methods[method]++
	m.totMethods[method]++
	if carriesAuth(req.Header) {
		m.cur.httpAuth++
	}
	now := m.now()
	if m.hasTW && !m.tw.Contains(now) {
		m.cur.outside++
	}
	cut := now.Add(-time.Second)
	i := 0
	for i < len(m.window) && !m.window[i].After(cut) {
		i++
	}
	m.window = append(m.window[i:], now)
	if len(m.window) > m.cur.peakRPS {
		m.cur.peakRPS = len(m.window)
	}
}

// carriesAuth reports a request sending credentials: an Authorization or
// Proxy-Authorization header, or any Cookie.
func carriesAuth(h http.Header) bool {
	return h.Get("Authorization") != "" || h.Get("Proxy-Authorization") != "" || h.Get("Cookie") != ""
}

// ProbeGate decides whether one more path probe may be sent to host and
// counts it. It matches sig.Engine.ProbeGate. A probe over the per-host
// budget is refused and counted as refused. A nil meter allows everything.
func (m *Meter) ProbeGate(host netip.Addr) bool {
	if m == nil {
		return true
	}
	host = host.Unmap()
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cur.gateCalls++
	if limit := m.budget.PathProbesPerHost; limit > 0 && m.base[host]+m.cur.probes[host] >= limit {
		m.cur.refused++
		return false
	}
	m.cur.probes[host]++
	return true
}

// Snapshot returns the live counters for the dashboard.
func (m *Meter) Snapshot() Snapshot {
	if m == nil {
		return Snapshot{}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	s := Snapshot{Packets: m.totPackets, Methods: make(map[string]int, len(m.totMethods))}
	var total int64
	for k, v := range m.totMethods {
		s.Methods[k] = v
		total += int64(v)
	}
	s.HTTPRequests = total
	if busy := busyTime(m.totBusy); busy > 0 {
		s.PPS = float64(m.totPackets) / busy.Seconds()
	}
	return s
}

func busyTime(ss []span) time.Duration {
	var busy time.Duration
	for _, s := range ss {
		busy += s.b.Sub(s.a)
	}
	return busy
}

// Transport wraps base so every request is counted in the meter of its
// context. A nil base means http.DefaultTransport.
func Transport(base http.RoundTripper) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	return countingTransport{base: base}
}

type countingTransport struct{ base http.RoundTripper }

func (t countingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	From(req.Context()).CountHTTP(req)
	return t.base.RoundTrip(req)
}

// Allowlist is the part of scope.Scope the receipt needs; scope.Scope
// satisfies it. CheckPrefix returns nil only for a prefix fully in scope.
type Allowlist interface {
	CheckPrefix(netip.Prefix) error
}

// Receipt is the stored and displayed safety record of one run.
type Receipt struct {
	RunID int64 `json:"run_id"`

	NmapInvocations   int      `json:"nmap_invocations"`
	NmapRawReported   int      `json:"nmap_raw_reported"`
	NmapPackets       int64    `json:"nmap_packets"`
	NmapElapsedMs     int64    `json:"nmap_elapsed_ms"`
	NmapBusyMs        int64    `json:"nmap_busy_ms"`
	NmapPeakInvPPS    float64  `json:"nmap_peak_invocation_pps"`
	ConfiguredMaxRate int      `json:"configured_max_rate"` // run budget, packets/s
	PolicyPPS         int      `json:"policy_pps"`
	PerWorkerRate     int      `json:"per_worker_rate"`
	ArgvSHA256        string   `json:"argv_sha256"`
	ArgvSample        []string `json:"argv_sample"`

	HTTPGet       int64   `json:"http_get"`
	HTTPHead      int64   `json:"http_head"`
	HTTPOther     int64   `json:"http_other"`
	HTTPAuth      int64   `json:"http_auth_headers"`
	HTTPPeakRPS   float64 `json:"http_peak_rps"`
	HTTPRateLimit float64 `json:"http_rate_limit"`
	HTTPBurst     int     `json:"http_burst"`

	TargetsChecked          int64 `json:"targets_checked"`
	TargetsOutsideAllowlist int64 `json:"targets_outside_allowlist"`

	TimeWindow    string `json:"time_window"` // "HH:MM-HH:MM" or empty
	OutsideWindow int64  `json:"outside_window"`

	PathProbeBudget   int   `json:"path_probe_budget"`
	PathProbes        int64 `json:"path_probes"`
	PathProbesRefused int64 `json:"path_probes_refused"`
	PathProbesMaxHost int   `json:"path_probes_max_host"` // busiest host, accumulated over resumes
	// PathProbeSignatures is how many enabled signatures send path probes;
	// PathProbeGateCalls how often the gate was consulted.
	PathProbeSignatures int   `json:"path_probe_signatures"`
	PathProbeGateCalls  int64 `json:"path_probe_gate_calls"`
	// PathProbeWebServices is how many web services were evaluated.
	PathProbeWebServices int64 `json:"path_probe_web_services"`
	// ProbeHosts is the per-host probe count of this Drain; Save adds it to
	// the stored counts. Not part of the JSON report.
	ProbeHosts map[string]int `json:"-"`

	UpdatedAt time.Time `json:"updated_at"`
}

// rateSeconds is the time the packets were sent over: nmap busy time, or
// the summed elapsed time when no start/end was recorded; 0 when neither is
// known.
func (r Receipt) rateSeconds() float64 {
	if r.NmapBusyMs > 0 {
		return float64(r.NmapBusyMs) / 1000
	}
	return float64(r.NmapElapsedMs) / 1000
}

// EffectivePPS is the run's average nmap rate: packets over the time at
// least one nmap process was running. It is 0 when that time is unknown.
func (r Receipt) EffectivePPS() float64 {
	secs := r.rateSeconds()
	if secs <= 0 {
		return 0
	}
	return float64(r.NmapPackets) / secs
}

// Receipt returns the measurements since the last Drain without resetting
// them; allow re-checks every target operand passed to nmap (nil skips the
// check, which then reports "unmeasured"). The caller fills RunID and the
// runner-owned limits (PerWorkerRate, HTTPRateLimit, HTTPBurst).
func (m *Meter) Receipt(allow Allowlist) Receipt {
	if m == nil {
		return Receipt{}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.receiptLocked(allow)
}

// Drain returns the measurements since the previous Drain and resets them,
// so the result can be added to the stored receipt exactly once. Always call
// Save with Drain output, never with a repeated Receipt.
func (m *Meter) Drain(allow Allowlist) Receipt {
	if m == nil {
		return Receipt{}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	r := m.receiptLocked(allow)
	for h, n := range m.cur.probes {
		m.base[h] += n
	}
	m.cur = newAcc()
	return r
}

func (m *Meter) receiptLocked(allow Allowlist) Receipt {
	var r Receipt
	c := &m.cur
	r.NmapInvocations = c.invocations
	r.NmapRawReported = c.rawReported
	r.NmapPackets = c.packets
	r.NmapElapsedMs = c.elapsed.Milliseconds()
	r.NmapBusyMs = busyTime(c.busy).Milliseconds()
	r.NmapPeakInvPPS = c.peakInvPPS
	r.ConfiguredMaxRate, r.PolicyPPS = m.budget.RunPPS, m.budget.PolicyPPS
	if c.invocations > 0 {
		r.ArgvSHA256 = hex.EncodeToString(c.argvHash.Sum(nil))
	}
	r.ArgvSample = append([]string(nil), c.argvSample...)
	for method, n := range c.methods {
		switch method {
		case http.MethodGet:
			r.HTTPGet += int64(n)
		case http.MethodHead:
			r.HTTPHead += int64(n)
		default:
			r.HTTPOther += int64(n)
		}
	}
	r.HTTPAuth = c.httpAuth
	r.HTTPPeakRPS = float64(c.peakRPS)
	if allow != nil {
		for _, p := range c.targets {
			n := addrCount(p)
			r.TargetsChecked += n
			if allow.CheckPrefix(p) != nil {
				r.TargetsOutsideAllowlist += n
			}
		}
	}
	if m.hasTW {
		r.TimeWindow = m.tw.String()
	}
	r.OutsideWindow = c.outside
	r.PathProbeBudget = max(m.budget.PathProbesPerHost, 0)
	r.PathProbesRefused = c.refused
	r.PathProbeSignatures = m.pathSigs
	r.PathProbeGateCalls = c.gateCalls
	r.PathProbeWebServices = c.webSvcs
	if len(c.probes) > 0 {
		r.ProbeHosts = make(map[string]int, len(c.probes))
	}
	for h, n := range c.probes {
		r.PathProbes += int64(n)
		r.ProbeHosts[h.String()] = n
	}
	for h, n := range m.base {
		r.PathProbesMaxHost = max(r.PathProbesMaxHost, n+c.probes[h])
	}
	for h, n := range c.probes {
		r.PathProbesMaxHost = max(r.PathProbesMaxHost, m.base[h]+n)
	}
	return r
}

// addrCount is the number of addresses in p, capped for huge IPv6 prefixes.
func addrCount(p netip.Prefix) int64 {
	host := p.Addr().BitLen() - p.Bits()
	if host >= 62 {
		return 1 << 62
	}
	return 1 << host
}
