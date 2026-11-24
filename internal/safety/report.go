package safety

import (
	"fmt"
	"math"
	"strings"
)

// Check is one pass/fail row of the receipt with the value that was
// measured.
type Check struct {
	Name     string `json:"name"`
	OK       bool   `json:"ok"`
	Measured string `json:"measured"`
	Detail   string `json:"detail"`
}

// Report is the receipt with derived values and the pass/fail checks: the
// body of GET /runs/{id}/safety.json and of `ramparteye audit <run>`.
type Report struct {
	Receipt
	EffectivePPS float64  `json:"effective_pps"`
	OK           bool     `json:"ok"`
	Checks       []Check  `json:"checks"`
	Notes        []string `json:"notes"`
}

// BuildReport derives the five checks from r: scope respected, rate within
// budget, GET/HEAD only, time window respected and path probe budget.
func BuildReport(r Receipt) Report {
	rep := Report{Receipt: r, EffectivePPS: round1(r.EffectivePPS()), OK: true}
	add := func(name string, ok bool, measured, detail string, a ...any) {
		rep.Checks = append(rep.Checks, Check{Name: name, OK: ok, Measured: measured, Detail: fmt.Sprintf(detail, a...)})
		rep.OK = rep.OK && ok
	}

	add("scope respected", r.TargetsOutsideAllowlist == 0,
		fmt.Sprintf("%d outside", r.TargetsOutsideAllowlist),
		"%d addresses re-checked after the run, %d outside the allowed scope",
		r.TargetsChecked, r.TargetsOutsideAllowlist)

	rateOK := true
	var parts []string
	nmapDetail := fmt.Sprintf("%.1f packets/s (%d packets in %.1f s of nmap time)",
		rep.EffectivePPS, r.NmapPackets, float64(r.NmapBusyMs)/1000)
	if r.ConfiguredMaxRate > 0 {
		rateOK = rateOK && rep.EffectivePPS <= float64(r.ConfiguredMaxRate)
		nmapDetail += fmt.Sprintf(", run budget %d/s", r.ConfiguredMaxRate)
	}
	if r.PolicyPPS > 0 {
		rateOK = rateOK && rep.EffectivePPS <= float64(r.PolicyPPS)
		nmapDetail += fmt.Sprintf(", policy limit %d/s", r.PolicyPPS)
	}
	if r.ConfiguredMaxRate <= 0 && r.PolicyPPS <= 0 {
		nmapDetail += ", no packet limit set"
	}
	parts = append(parts, nmapDetail)
	if r.HTTPRateLimit > 0 {
		capRPS := r.HTTPRateLimit + float64(r.HTTPBurst)
		rateOK = rateOK && r.HTTPPeakRPS <= capRPS
		parts = append(parts, fmt.Sprintf("HTTP peak %.0f requests in a 1 s window against %.0f/s plus burst %d",
			r.HTTPPeakRPS, r.HTTPRateLimit, r.HTTPBurst))
	}
	measured := fmt.Sprintf("%.1f pps", rep.EffectivePPS)
	if r.HTTPRateLimit > 0 {
		measured += fmt.Sprintf(", %.0f req/s", r.HTTPPeakRPS)
	}
	rep.Checks = append(rep.Checks, Check{Name: "rate within budget", OK: rateOK, Measured: measured, Detail: strings.Join(parts, "; ")})
	rep.OK = rep.OK && rateOK

	add("GET/HEAD only", r.HTTPOther == 0,
		fmt.Sprintf("%d other", r.HTTPOther),
		"GET %d, HEAD %d, other %d, %d with credentials", r.HTTPGet, r.HTTPHead, r.HTTPOther, r.HTTPAuth)

	if r.TimeWindow == "" {
		add("time window respected", r.OutsideWindow == 0, fmt.Sprintf("%d outside", r.OutsideWindow),
			"no window configured, %d requests or nmap runs counted outside it", r.OutsideWindow)
	} else {
		add("time window respected", r.OutsideWindow == 0, fmt.Sprintf("%d outside", r.OutsideWindow),
			"window %s, %d requests or nmap runs outside it", r.TimeWindow, r.OutsideWindow)
	}

	budget := "unlimited"
	if r.PathProbeBudget > 0 {
		budget = fmt.Sprint(r.PathProbeBudget)
	}
	add("path probe budget", r.PathProbeBudget <= 0 || r.PathProbesMaxHost <= r.PathProbeBudget,
		fmt.Sprintf("%d max per host", r.PathProbesMaxHost),
		"%d probes sent, busiest host %d against a budget of %s per host, %d refused",
		r.PathProbes, r.PathProbesMaxHost, budget, r.PathProbesRefused)

	if r.NmapRawReported < r.NmapInvocations {
		rep.Notes = append(rep.Notes, fmt.Sprintf(
			"%d of %d nmap runs did not report a packet counter (unprivileged scan): their packets are estimated from the XML (addresses x ports or probes).",
			r.NmapInvocations-r.NmapRawReported, r.NmapInvocations))
	}
	rep.Notes = append(rep.Notes,
		"The average is taken over the time at least one nmap process was running; K processes get max_rate/K each, so over intervals shorter than 1 s the instantaneous rate can exceed the limit.",
		"Version detection probes (-sV) use ordinary TCP connections and are not covered by nmap's packet counter or --max-rate.")
	return rep
}

func round1(f float64) float64 { return math.Round(f*10) / 10 }
