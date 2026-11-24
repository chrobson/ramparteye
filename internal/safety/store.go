package safety

import (
	"context"
	"errors"
	"fmt"
	"net/netip"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// DB is satisfied by *pgxpool.Pool, *pgx.Conn, pgx.Tx and store's DBTX.
type DB interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// ErrNoReceipt is returned by Load for a run without a receipt.
var ErrNoReceipt = errors.New("no safety receipt for this run")

// nzLeast keeps the most restrictive non-zero value of a limit column when
// a resumed run is saved again (0 = no limit).
func nzLeast(col string) string {
	return fmt.Sprintf("%[1]s = CASE WHEN EXCLUDED.%[1]s = 0 THEN run_safety.%[1]s "+
		"WHEN run_safety.%[1]s = 0 THEN EXCLUDED.%[1]s ELSE LEAST(run_safety.%[1]s, EXCLUDED.%[1]s) END", col)
}

// Save adds r to the run's receipt, in one statement. Counters add up (a
// paused run resumed later is one run), peaks keep the maximum, limits keep
// the most restrictive non-zero value, the time window the latest non-empty
// one, and the first command lines are kept from the first write. Per-host
// path probe counts in r.ProbeHosts are added to the stored counts.
//
// r must be the output of (*Meter).Drain: it holds only what happened since
// the previous Drain. Saving a repeated Receipt would count it twice.
func Save(ctx context.Context, db DB, r Receipt) error {
	sample := r.ArgvSample
	if sample == nil {
		sample = []string{}
	}
	norm := make(map[string]int32, len(r.ProbeHosts))
	for h, n := range r.ProbeHosts {
		a, err := netip.ParseAddr(h)
		if err != nil {
			return fmt.Errorf("save safety receipt run %d: probe host %q: %w", r.RunID, h, err)
		}
		norm[a.Unmap().WithZone("").String()] += int32(n)
	}
	hosts, counts := make([]string, 0, len(norm)), make([]int32, 0, len(norm))
	for h, n := range norm {
		hosts, counts = append(hosts, h), append(counts, n)
	}
	_, err := db.Exec(ctx, `
WITH probes AS (
    INSERT INTO run_safety_probes (run_id, host, probes)
    SELECT $1, h::inet, c FROM unnest($28::text[], $29::int[]) AS u(h, c)
    ON CONFLICT (run_id, host) DO UPDATE SET probes = run_safety_probes.probes + EXCLUDED.probes
    RETURNING 1
)
INSERT INTO run_safety (run_id, nmap_invocations, nmap_raw_reported, nmap_packets, nmap_elapsed_ms,
    nmap_busy_ms, nmap_peak_invocation_pps, configured_max_rate, per_worker_rate, argv_sha256, argv_sample,
    http_get, http_head, http_other, http_auth_headers, http_peak_rps, http_rate_limit, http_burst,
    targets_checked, targets_outside_allowlist,
    policy_pps, path_probe_budget, path_probes, path_probes_refused,
    time_window, outside_window, path_probe_signatures, path_probe_gate_calls, path_probe_web_services, unchecked_invocations, path_probe_signatures_known, updated_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$30,$31,$32,$33, now())
ON CONFLICT (run_id) DO UPDATE SET
    nmap_invocations = run_safety.nmap_invocations + EXCLUDED.nmap_invocations,
    nmap_raw_reported = run_safety.nmap_raw_reported + EXCLUDED.nmap_raw_reported,
    nmap_packets = run_safety.nmap_packets + EXCLUDED.nmap_packets,
    nmap_elapsed_ms = run_safety.nmap_elapsed_ms + EXCLUDED.nmap_elapsed_ms,
    nmap_busy_ms = run_safety.nmap_busy_ms + EXCLUDED.nmap_busy_ms,
    nmap_peak_invocation_pps = GREATEST(run_safety.nmap_peak_invocation_pps, EXCLUDED.nmap_peak_invocation_pps),
    `+nzLeast("configured_max_rate")+`,
    `+nzLeast("per_worker_rate")+`,
    argv_sha256 = CASE WHEN run_safety.argv_sha256 = '' THEN EXCLUDED.argv_sha256 ELSE run_safety.argv_sha256 END,
    argv_sample = CASE WHEN cardinality(run_safety.argv_sample) = 0 THEN EXCLUDED.argv_sample ELSE run_safety.argv_sample END,
    http_get = run_safety.http_get + EXCLUDED.http_get,
    http_head = run_safety.http_head + EXCLUDED.http_head,
    http_other = run_safety.http_other + EXCLUDED.http_other,
    http_auth_headers = run_safety.http_auth_headers + EXCLUDED.http_auth_headers,
    http_peak_rps = GREATEST(run_safety.http_peak_rps, EXCLUDED.http_peak_rps),
    http_rate_limit = CASE WHEN EXCLUDED.http_rate_limit = 0 THEN run_safety.http_rate_limit
        WHEN run_safety.http_rate_limit = 0 THEN EXCLUDED.http_rate_limit
        ELSE LEAST(run_safety.http_rate_limit, EXCLUDED.http_rate_limit) END,
    `+nzLeast("http_burst")+`,
    targets_checked = run_safety.targets_checked + EXCLUDED.targets_checked,
    targets_outside_allowlist = run_safety.targets_outside_allowlist + EXCLUDED.targets_outside_allowlist,
    `+nzLeast("policy_pps")+`,
    `+nzLeast("path_probe_budget")+`,
    path_probes = run_safety.path_probes + EXCLUDED.path_probes,
    path_probes_refused = run_safety.path_probes_refused + EXCLUDED.path_probes_refused,
    time_window = CASE WHEN EXCLUDED.time_window = '' THEN run_safety.time_window ELSE EXCLUDED.time_window END,
    outside_window = run_safety.outside_window + EXCLUDED.outside_window,
    path_probe_signatures = GREATEST(run_safety.path_probe_signatures, EXCLUDED.path_probe_signatures),
    path_probe_gate_calls = run_safety.path_probe_gate_calls + EXCLUDED.path_probe_gate_calls,
    path_probe_web_services = run_safety.path_probe_web_services + EXCLUDED.path_probe_web_services,
    unchecked_invocations = run_safety.unchecked_invocations + EXCLUDED.unchecked_invocations,
    path_probe_signatures_known = run_safety.path_probe_signatures_known OR EXCLUDED.path_probe_signatures_known,
    updated_at = now()`,
		r.RunID, r.NmapInvocations, r.NmapRawReported, r.NmapPackets, r.NmapElapsedMs,
		r.NmapBusyMs, float32(r.NmapPeakInvPPS), r.ConfiguredMaxRate, r.PerWorkerRate, r.ArgvSHA256, sample,
		r.HTTPGet, r.HTTPHead, r.HTTPOther, r.HTTPAuth, float32(r.HTTPPeakRPS), float32(r.HTTPRateLimit), r.HTTPBurst,
		r.TargetsChecked, r.TargetsOutsideAllowlist,
		r.PolicyPPS, r.PathProbeBudget, r.PathProbes, r.PathProbesRefused,
		r.TimeWindow, r.OutsideWindow, r.PathProbeSignatures, hosts, counts, r.PathProbeGateCalls, r.PathProbeWebServices,
		r.UncheckedInvocations, r.PathProbeSignaturesKnown)
	if err != nil {
		return fmt.Errorf("save safety receipt run %d: %w", r.RunID, err)
	}
	return nil
}

// Load returns the accumulated receipt of a run, or ErrNoReceipt.
func Load(ctx context.Context, db DB, runID int64) (Receipt, error) {
	r := Receipt{RunID: runID}
	var peakInv, peakRPS, httpLimit float32
	err := db.QueryRow(ctx, `
SELECT nmap_invocations, nmap_raw_reported, nmap_packets, nmap_elapsed_ms, nmap_busy_ms,
    nmap_peak_invocation_pps, configured_max_rate, per_worker_rate, argv_sha256, argv_sample,
    http_get, http_head, http_other, http_auth_headers, http_peak_rps, http_rate_limit, http_burst,
    targets_checked, targets_outside_allowlist,
    policy_pps, path_probe_budget, path_probes, path_probes_refused,
    (SELECT coalesce(max(probes), 0) FROM run_safety_probes WHERE run_id = $1),
    time_window, outside_window, path_probe_signatures, path_probe_gate_calls, path_probe_web_services, unchecked_invocations, path_probe_signatures_known, updated_at
FROM run_safety WHERE run_id = $1`, runID).Scan(
		&r.NmapInvocations, &r.NmapRawReported, &r.NmapPackets, &r.NmapElapsedMs, &r.NmapBusyMs,
		&peakInv, &r.ConfiguredMaxRate, &r.PerWorkerRate, &r.ArgvSHA256, &r.ArgvSample,
		&r.HTTPGet, &r.HTTPHead, &r.HTTPOther, &r.HTTPAuth, &peakRPS, &httpLimit, &r.HTTPBurst,
		&r.TargetsChecked, &r.TargetsOutsideAllowlist,
		&r.PolicyPPS, &r.PathProbeBudget, &r.PathProbes, &r.PathProbesRefused,
		&r.PathProbesMaxHost,
		&r.TimeWindow, &r.OutsideWindow, &r.PathProbeSignatures, &r.PathProbeGateCalls, &r.PathProbeWebServices, &r.UncheckedInvocations, &r.PathProbeSignaturesKnown, &r.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return r, ErrNoReceipt
	}
	if err != nil {
		return r, fmt.Errorf("load safety receipt run %d: %w", runID, err)
	}
	r.NmapPeakInvPPS, r.HTTPPeakRPS, r.HTTPRateLimit = float64(peakInv), float64(peakRPS), float64(httpLimit)
	return r, nil
}

// LoadProbes returns the path probes a run already spent per host; feed it to
// (*Meter).SeedProbes when resuming so the budget holds across resumes.
func LoadProbes(ctx context.Context, db DB, runID int64) (map[netip.Addr]int, error) {
	var raw map[string]int
	err := db.QueryRow(ctx, `SELECT coalesce(jsonb_object_agg(host(host), probes), '{}'::jsonb)
		FROM run_safety_probes WHERE run_id = $1`, runID).Scan(&raw)
	if err != nil {
		return nil, fmt.Errorf("load path probe counts run %d: %w", runID, err)
	}
	out := make(map[netip.Addr]int, len(raw))
	for h, n := range raw {
		a, err := netip.ParseAddr(h)
		if err != nil {
			return nil, fmt.Errorf("load path probe counts run %d: %w", runID, err)
		}
		out[a.Unmap()] = n
	}
	return out, nil
}
