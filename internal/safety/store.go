package safety

import (
	"context"
	"errors"
	"fmt"

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

// Save adds r to the run's receipt. Counters add up (a paused run resumed
// later is one run), peaks keep the maximum, the configured limits come from
// the latest write and the first command lines from the first.
func Save(ctx context.Context, db DB, r Receipt) error {
	sample := r.ArgvSample
	if sample == nil {
		sample = []string{}
	}
	_, err := db.Exec(ctx, `
INSERT INTO run_safety (run_id, nmap_invocations, nmap_raw_reported, nmap_packets, nmap_elapsed_ms,
    nmap_busy_ms, nmap_peak_invocation_pps, configured_max_rate, per_worker_rate, argv_sha256, argv_sample,
    http_get, http_head, http_other, http_auth_headers, http_peak_rps, http_rate_limit, http_burst,
    targets_checked, targets_outside_allowlist,
    policy_pps, path_probe_budget, path_probes, path_probes_refused, path_probes_max_host,
    time_window, outside_window, updated_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27, now())
ON CONFLICT (run_id) DO UPDATE SET
    nmap_invocations = run_safety.nmap_invocations + EXCLUDED.nmap_invocations,
    nmap_raw_reported = run_safety.nmap_raw_reported + EXCLUDED.nmap_raw_reported,
    nmap_packets = run_safety.nmap_packets + EXCLUDED.nmap_packets,
    nmap_elapsed_ms = run_safety.nmap_elapsed_ms + EXCLUDED.nmap_elapsed_ms,
    nmap_busy_ms = run_safety.nmap_busy_ms + EXCLUDED.nmap_busy_ms,
    nmap_peak_invocation_pps = GREATEST(run_safety.nmap_peak_invocation_pps, EXCLUDED.nmap_peak_invocation_pps),
    configured_max_rate = EXCLUDED.configured_max_rate,
    per_worker_rate = EXCLUDED.per_worker_rate,
    argv_sha256 = CASE WHEN run_safety.argv_sha256 = '' THEN EXCLUDED.argv_sha256 ELSE run_safety.argv_sha256 END,
    argv_sample = CASE WHEN cardinality(run_safety.argv_sample) = 0 THEN EXCLUDED.argv_sample ELSE run_safety.argv_sample END,
    http_get = run_safety.http_get + EXCLUDED.http_get,
    http_head = run_safety.http_head + EXCLUDED.http_head,
    http_other = run_safety.http_other + EXCLUDED.http_other,
    http_auth_headers = run_safety.http_auth_headers + EXCLUDED.http_auth_headers,
    http_peak_rps = GREATEST(run_safety.http_peak_rps, EXCLUDED.http_peak_rps),
    http_rate_limit = EXCLUDED.http_rate_limit,
    http_burst = EXCLUDED.http_burst,
    targets_checked = run_safety.targets_checked + EXCLUDED.targets_checked,
    targets_outside_allowlist = run_safety.targets_outside_allowlist + EXCLUDED.targets_outside_allowlist,
    policy_pps = EXCLUDED.policy_pps,
    path_probe_budget = EXCLUDED.path_probe_budget,
    path_probes = run_safety.path_probes + EXCLUDED.path_probes,
    path_probes_refused = run_safety.path_probes_refused + EXCLUDED.path_probes_refused,
    path_probes_max_host = GREATEST(run_safety.path_probes_max_host, EXCLUDED.path_probes_max_host),
    time_window = EXCLUDED.time_window,
    outside_window = run_safety.outside_window + EXCLUDED.outside_window,
    updated_at = now()`,
		r.RunID, r.NmapInvocations, r.NmapRawReported, r.NmapPackets, r.NmapElapsedMs,
		r.NmapBusyMs, float32(r.NmapPeakInvPPS), r.ConfiguredMaxRate, r.PerWorkerRate, r.ArgvSHA256, sample,
		r.HTTPGet, r.HTTPHead, r.HTTPOther, r.HTTPAuth, float32(r.HTTPPeakRPS), float32(r.HTTPRateLimit), r.HTTPBurst,
		r.TargetsChecked, r.TargetsOutsideAllowlist,
		r.PolicyPPS, r.PathProbeBudget, r.PathProbes, r.PathProbesRefused, r.PathProbesMaxHost,
		r.TimeWindow, r.OutsideWindow)
	if err != nil {
		return fmt.Errorf("save safety receipt run %d: %w", r.RunID, err)
	}
	return nil
}

// Load returns the receipt of a run, or ErrNoReceipt.
func Load(ctx context.Context, db DB, runID int64) (Receipt, error) {
	r := Receipt{RunID: runID}
	var peakInv, peakRPS, httpLimit float32
	err := db.QueryRow(ctx, `
SELECT nmap_invocations, nmap_raw_reported, nmap_packets, nmap_elapsed_ms, nmap_busy_ms,
    nmap_peak_invocation_pps, configured_max_rate, per_worker_rate, argv_sha256, argv_sample,
    http_get, http_head, http_other, http_auth_headers, http_peak_rps, http_rate_limit, http_burst,
    targets_checked, targets_outside_allowlist,
    policy_pps, path_probe_budget, path_probes, path_probes_refused, path_probes_max_host,
    time_window, outside_window, updated_at
FROM run_safety WHERE run_id = $1`, runID).Scan(
		&r.NmapInvocations, &r.NmapRawReported, &r.NmapPackets, &r.NmapElapsedMs, &r.NmapBusyMs,
		&peakInv, &r.ConfiguredMaxRate, &r.PerWorkerRate, &r.ArgvSHA256, &r.ArgvSample,
		&r.HTTPGet, &r.HTTPHead, &r.HTTPOther, &r.HTTPAuth, &peakRPS, &httpLimit, &r.HTTPBurst,
		&r.TargetsChecked, &r.TargetsOutsideAllowlist,
		&r.PolicyPPS, &r.PathProbeBudget, &r.PathProbes, &r.PathProbesRefused, &r.PathProbesMaxHost,
		&r.TimeWindow, &r.OutsideWindow, &r.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return r, ErrNoReceipt
	}
	if err != nil {
		return r, fmt.Errorf("load safety receipt run %d: %w", runID, err)
	}
	r.NmapPeakInvPPS, r.HTTPPeakRPS, r.HTTPRateLimit = float64(peakInv), float64(peakRPS), float64(httpLimit)
	return r, nil
}
