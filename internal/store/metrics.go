package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/chrobson/ramparteye/internal/model"
)

// The queries in this file feed GET /healthz and GET /metrics. They return
// aggregates only (counts, ids and timestamps), never anything observed on a
// scanned host, and each one is a single statement.

// Ping runs the cheapest possible query: the database answers.
func (s *Store) Ping(ctx context.Context) error {
	var one int
	return s.db.QueryRow(ctx, `SELECT 1`).Scan(&one)
}

// ScanRunCounts returns the number of scan runs per status; a status
// without runs is absent. Imports are not scans and are not counted.
func (s *Store) ScanRunCounts(ctx context.Context) (map[string]int, error) {
	rows, err := s.db.Query(ctx, `SELECT status, count(*) FROM scan_runs WHERE kind = 'scan' GROUP BY status`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var status string
		var n int
		if err := rows.Scan(&status, &n); err != nil {
			return nil, err
		}
		out[status] = n
	}
	return out, rows.Err()
}

// FinishedScan is the newest scan run that finished with status done.
type FinishedScan struct {
	ID         int64
	FinishedAt time.Time
	// Duration is the scanning time of the run (0 when not recorded).
	Duration time.Duration
}

// LastFinishedScan returns the scan run that finished (status done) most
// recently, or nil when no scan has.
func (s *Store) LastFinishedScan(ctx context.Context) (*FinishedScan, error) {
	var f FinishedScan
	var ms *int64
	err := s.db.QueryRow(ctx, `SELECT id, finished_at, duration_ms FROM scan_runs
		WHERE kind = 'scan' AND status = 'done' AND finished_at IS NOT NULL
		ORDER BY finished_at DESC, id DESC LIMIT 1`).Scan(&f.ID, &f.FinishedAt, &ms)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if ms != nil {
		f.Duration = time.Duration(*ms) * time.Millisecond
	}
	return &f, nil
}

// DetectionGroup counts the detections of a run that share a recorded
// severity (evidence["severity"], empty when the signature recorded none)
// and a category. The effective severity is derived from both by
// dojo.DetectionSeverity, so the rule lives in one place.
type DetectionGroup struct {
	Severity string
	Category string
	N        int
}

// RunInventory is what the latest finished run and the latest diff hold.
type RunInventory struct {
	// RunID is the run chosen like the dashboard does (see LatestDoneRun);
	// 0 = no run has finished.
	RunID      int64
	Services   int
	Detections []DetectionGroup // ordered by category, then severity
	// DiffRunID is the newest run whose diff was applied (0 = none) and
	// Changes counts its changes per kind (a kind without changes is absent).
	DiffRunID int64
	Changes   map[model.ChangeKind]int
}

// LatestRunInventory counts the services and detections of the latest
// finished run and the changes of the latest applied diff, in one statement.
func (s *Store) LatestRunInventory(ctx context.Context) (RunInventory, error) {
	rows, err := s.db.Query(ctx, `
WITH latest AS (
	SELECT id FROM scan_runs r WHERE status = 'done'
	ORDER BY (kind = 'scan') DESC, EXISTS (SELECT 1 FROM diff_runs d WHERE d.run_id = r.id) DESC, id DESC
	LIMIT 1),
last_diff AS (SELECT run_id FROM diff_runs ORDER BY run_id DESC LIMIT 1)
SELECT 'run', '', '', id FROM latest
UNION ALL
SELECT 'services', '', '', count(*) FROM services WHERE run_id = (SELECT id FROM latest)
UNION ALL
SELECT 'detection', coalesce(d.evidence->>'severity', ''), d.category, count(*)
	FROM detections d JOIN services s ON s.id = d.service_id
	WHERE s.run_id = (SELECT id FROM latest) GROUP BY 2, 3
UNION ALL
SELECT 'diff', '', '', run_id FROM last_diff
UNION ALL
SELECT 'change', kind, '', count(*) FROM changes WHERE run_id = (SELECT run_id FROM last_diff) GROUP BY kind
ORDER BY 1, 3, 2`)
	if err != nil {
		return RunInventory{}, err
	}
	defer rows.Close()
	out := RunInventory{Changes: map[model.ChangeKind]int{}}
	for rows.Next() {
		var what, a, b string
		var n int64
		if err := rows.Scan(&what, &a, &b, &n); err != nil {
			return RunInventory{}, err
		}
		switch what {
		case "run":
			out.RunID = n
		case "services":
			out.Services = int(n)
		case "detection":
			out.Detections = append(out.Detections, DetectionGroup{Severity: a, Category: b, N: int(n)})
		case "diff":
			out.DiffRunID = n
		case "change":
			out.Changes[model.ChangeKind(a)] = int(n)
		default:
			return RunInventory{}, fmt.Errorf("inventory row %q", what)
		}
	}
	return out, rows.Err()
}

// LatestReceiptRun returns the newest scan run that is over (done, failed or
// cancelled) and has a safety receipt; 0 when there is none. A run that
// stopped early still sent traffic, so its receipt counts.
func (s *Store) LatestReceiptRun(ctx context.Context) (int64, error) {
	var id int64
	err := s.db.QueryRow(ctx, `SELECT r.id FROM scan_runs r JOIN run_safety s ON s.run_id = r.id
		WHERE r.kind = 'scan' AND r.status IN ('done', 'failed', 'cancelled')
		ORDER BY r.id DESC LIMIT 1`).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, nil
	}
	return id, err
}
