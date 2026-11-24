package safety

import (
	"fmt"
	"math"
	"strings"
)

// Status is the outcome of one check. A check passes only when something
// was measured and found within limits; when the measurement could not be
// made the status is StatusUnmeasured, never StatusPass.
type Status string

const (
	StatusPass       Status = "pass"
	StatusFail       Status = "fail"
	StatusUnmeasured Status = "unmeasured"
)

// Check is one row of the receipt with the value that was measured. OK is
// true only for StatusPass.
type Check struct {
	Name     string `json:"name"`
	Status   Status `json:"status"`
	OK       bool   `json:"ok"`
	Measured string `json:"measured"`
	Detail   string `json:"detail"`
}

// Report is the receipt with derived values and the checks: the body of
// GET /runs/{id}/safety.json and of `ramparteye audit <run>`. OK is true
// only when every check passed (an unmeasured check makes it false).
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
	add := func(name string, st Status, measured, detail string, a ...any) {
		rep.Checks = append(rep.Checks, Check{Name: name, Status: st, OK: st == StatusPass,
			Measured: measured, Detail: fmt.Sprintf(detail, a...)})
		rep.OK = rep.OK && st == StatusPass
	}
	passIf := func(ok bool) Status {
		if ok {
			return StatusPass
		}
		return StatusFail
	}

	// Scope.
	switch {
	case r.NmapInvocations > 0 && r.TargetsChecked == 0:
		add("scope respected", StatusUnmeasured, "0 checked",
			"%d nmap runs but no target address was re-checked against the scope", r.NmapInvocations)
	default:
		add("scope respected", passIf(r.TargetsOutsideAllowlist == 0),
			fmt.Sprintf("%d outside", r.TargetsOutsideAllowlist),
			"%d addresses re-checked after the run, %d outside the allowed scope",
			r.TargetsChecked, r.TargetsOutsideAllowlist)
	}

	// Rate: average and per-invocation peak of nmap, HTTP peak.
	var parts []string
	failed, unmeasured := false, false
	secs := r.rateSeconds()
	avg := rep.EffectivePPS
	switch {
	case r.NmapPackets > 0 && secs <= 0:
		unmeasured = true
		parts = append(parts, fmt.Sprintf("%d packets sent but no nmap run time was recorded", r.NmapPackets))
	default:
		parts = append(parts, fmt.Sprintf("%.1f packets/s average (%d packets in %.1f s of nmap time), peak run %.1f packets/s",
			avg, r.NmapPackets, secs, r.NmapPeakInvPPS))
		limits := 0
		for _, l := range []struct {
			name string
			v    int
		}{{"run budget", r.ConfiguredMaxRate}, {"policy limit", r.PolicyPPS}} {
			if l.v <= 0 {
				continue
			}
			limits++
			if avg > float64(l.v) || r.NmapPeakInvPPS > float64(l.v) {
				failed = true
			}
			parts = append(parts, fmt.Sprintf("%s %d/s", l.name, l.v))
		}
		if limits == 0 {
			parts = append(parts, "no packet limit set")
		}
	}
	if r.HTTPRateLimit > 0 {
		capRPS := r.HTTPRateLimit + float64(r.HTTPBurst)
		failed = failed || r.HTTPPeakRPS > capRPS
		parts = append(parts, fmt.Sprintf("HTTP peak %.0f requests in a 1 s window against %.0f/s plus burst %d",
			r.HTTPPeakRPS, r.HTTPRateLimit, r.HTTPBurst))
	}
	measured := fmt.Sprintf("%.1f pps (peak %.1f)", avg, r.NmapPeakInvPPS)
	if r.HTTPRateLimit > 0 {
		measured += fmt.Sprintf(", %.0f req/s", r.HTTPPeakRPS)
	}
	st := StatusPass
	switch {
	case failed:
		st = StatusFail
	case unmeasured:
		st = StatusUnmeasured
		measured = "no run time"
	}
	add("rate within budget", st, measured, "%s", strings.Join(parts, "; "))

	add("GET/HEAD only", passIf(r.HTTPOther == 0),
		fmt.Sprintf("%d other", r.HTTPOther),
		"GET %d, HEAD %d, other %d, %d with credentials", r.HTTPGet, r.HTTPHead, r.HTTPOther, r.HTTPAuth)

	if r.TimeWindow == "" {
		add("time window respected", passIf(r.OutsideWindow == 0), fmt.Sprintf("%d outside", r.OutsideWindow),
			"no window configured, %d requests or nmap runs counted outside it", r.OutsideWindow)
	} else {
		add("time window respected", passIf(r.OutsideWindow == 0), fmt.Sprintf("%d outside", r.OutsideWindow),
			"window %s, %d requests or nmap runs outside it", r.TimeWindow, r.OutsideWindow)
	}

	budget := "unlimited"
	if r.PathProbeBudget > 0 {
		budget = fmt.Sprint(r.PathProbeBudget)
	}
	probeMeasured := fmt.Sprintf("%d max per host", r.PathProbesMaxHost)
	if r.PathProbeSignatures > 0 && r.PathProbeGateCalls == 0 && r.PathProbes == 0 && r.PathProbesRefused == 0 {
		add("path probe budget", StatusUnmeasured, probeMeasured,
			"%d enabled path-probe signatures but the probe gate was never consulted", r.PathProbeSignatures)
	} else {
		add("path probe budget", passIf(r.PathProbeBudget <= 0 || r.PathProbesMaxHost <= r.PathProbeBudget),
			probeMeasured,
			"%d probes sent, busiest host %d against a budget of %s per host, %d refused",
			r.PathProbes, r.PathProbesMaxHost, budget, r.PathProbesRefused)
	}

	if r.NmapRawReported < r.NmapInvocations {
		rep.Notes = append(rep.Notes, fmt.Sprintf(
			"%d of %d nmap runs did not report a packet counter (unprivileged scan): their packets are estimated from the XML (addresses x ports or probes).",
			r.NmapInvocations-r.NmapRawReported, r.NmapInvocations))
	}
	rep.Notes = append(rep.Notes,
		"The average is taken over the time at least one nmap process was running; K processes get max_rate/K each, so over intervals shorter than 1 s the instantaneous rate can exceed the limit.",
		"The peak divides each nmap run's packets by its elapsed time, at least 1 s.",
		"Version detection probes (-sV) use ordinary TCP connections and are not covered by nmap's packet counter or --max-rate.")
	return rep
}

func round1(f float64) float64 { return math.Round(f*10) / 10 }
