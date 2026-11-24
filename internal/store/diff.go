package store

import (
	"context"

	"github.com/jackc/pgx/v5"

	"github.com/chrobson/ramparteye/internal/model"
)

// diffLockID is the transaction advisory lock key serialising diff
// application.
const diffLockID = 4000001

// PrevScanRunID returns the newest finished scan run older than runID, or 0.
// Imports are never a baseline: they hold only the hosts of their file and
// would make the next scan report everything else as changed or gone.
func (s *Store) PrevScanRunID(ctx context.Context, runID int64) (int64, error) {
	var id *int64
	err := s.db.QueryRow(ctx, `SELECT max(id) FROM scan_runs
		WHERE id < $1 AND status = 'done' AND kind = 'scan'`, runID).Scan(&id)
	if err != nil || id == nil {
		return 0, err
	}
	return *id, nil
}

// RunIsImport reports whether runID is an import run.
func (s *Store) RunIsImport(ctx context.Context, runID int64) (bool, error) {
	var ok bool
	err := s.db.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM scan_runs WHERE id = $1 AND kind = 'import')`,
		runID).Scan(&ok)
	return ok, err
}

// DiffApplied reports whether the diff of runID has been applied.
func (s *Store) DiffApplied(ctx context.Context, runID int64) (bool, error) {
	var ok bool
	err := s.db.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM diff_runs WHERE run_id = $1)`, runID).Scan(&ok)
	return ok, err
}

// MarkDiffApplied records that the diff of runID was applied against
// prevRunID (0 = no baseline) and produced n changes.
func (s *Store) MarkDiffApplied(ctx context.Context, runID, prevRunID int64, n int) error {
	_, err := s.db.Exec(ctx, `INSERT INTO diff_runs (run_id, prev_run_id, changes)
		VALUES ($1, nullif($2::bigint, 0), $3)`, runID, prevRunID, n)
	return err
}

// LockDiff serialises diff application until the transaction ends. It only
// has an effect inside InTx.
func (s *Store) LockDiff(ctx context.Context) error {
	_, err := s.db.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, diffLockID)
	return err
}

// inScope is a SQL predicate: address column col lies in the scope of the
// run given by parameter p. An import covers exactly the hosts in its file
// (its host_obs and services); a scan covers its chunk prefixes; a scan
// without chunks covers everything.
func inScope(col, p string) string {
	return `(CASE WHEN EXISTS (SELECT 1 FROM scan_runs r WHERE r.id = ` + p + ` AND r.kind = 'import') THEN
		   EXISTS (SELECT 1 FROM host_obs h WHERE h.run_id = ` + p + ` AND h.ip = ` + col + `)
		   OR EXISTS (SELECT 1 FROM services s2 WHERE s2.run_id = ` + p + ` AND s2.ip = ` + col + `)
		 ELSE NOT EXISTS (SELECT 1 FROM scan_chunks c WHERE c.run_id = ` + p + `)
		   OR EXISTS (SELECT 1 FROM scan_chunks c WHERE c.run_id = ` + p + ` AND ` + col + ` <<= c.cidr) END)`
}

// RunServices loads every service observed in a run.
func (s *Store) RunServices(ctx context.Context, runID int64) ([]model.ServiceObs, error) {
	return s.RunServicesInScope(ctx, runID, runID)
}

// RunServicesInScope loads the services of runID inside the scope of
// scopeRunID, so hosts outside the current run's targets are not reported
// as gone.
func (s *Store) RunServicesInScope(ctx context.Context, runID, scopeRunID int64) ([]model.ServiceObs, error) {
	rows, err := s.db.Query(ctx, `
		SELECT id, run_id, host(ip), port, proto, vhost, product, version, extrainfo, cpe, banner
		FROM services s WHERE run_id = $1 AND `+inScope("s.ip", "$2")+`
		ORDER BY ip, port, proto, vhost`, runID, scopeRunID)
	if err != nil {
		return nil, err
	}
	return collect(rows, func(r pgx.Rows) (model.ServiceObs, error) {
		var sv model.ServiceObs
		var ip string
		var port int
		if err := r.Scan(&sv.ID, &sv.RunID, &ip, &port, &sv.Key.Proto, &sv.Key.VHost,
			&sv.Product, &sv.Version, &sv.ExtraInfo, &sv.CPE, &sv.Banner); err != nil {
			return sv, err
		}
		sv.Key.Port = uint16(port)
		var err error
		sv.Key.IP, err = parseAddr(ip)
		return sv, err
	})
}

// RunHostObs loads the host observations of a run.
func (s *Store) RunHostObs(ctx context.Context, runID int64) ([]model.HostObs, error) {
	rows, err := s.db.Query(ctx, `SELECT run_id, host(ip), hostname, up FROM host_obs
		WHERE run_id = $1 ORDER BY ip`, runID)
	if err != nil {
		return nil, err
	}
	return collect(rows, func(r pgx.Rows) (model.HostObs, error) {
		var h model.HostObs
		var ip string
		if err := r.Scan(&h.RunID, &ip, &h.Hostname, &h.Up); err != nil {
			return h, err
		}
		var err error
		h.IP, err = parseAddr(ip)
		return h, err
	})
}

// RunHTTPStatus returns the HTTP status of the probed services of the given
// runs, keyed by service id.
func (s *Store) RunHTTPStatus(ctx context.Context, runIDs ...int64) (map[int64]int, error) {
	return s.serviceInts(ctx, `SELECT o.service_id, o.status
		FROM http_obs o JOIN services s ON s.id = o.service_id
		WHERE s.run_id = ANY($1) AND o.status IS NOT NULL`, runIDs)
}

// RunLatencies returns the measured HTTP response times (ms) of the services
// of the given runs, keyed by service id.
func (s *Store) RunLatencies(ctx context.Context, runIDs ...int64) (map[int64]int, error) {
	return s.serviceInts(ctx, `SELECT o.service_id, o.response_ms
		FROM http_obs o JOIN services s ON s.id = o.service_id
		WHERE s.run_id = ANY($1) AND o.response_ms > 0`, runIDs)
}

func (s *Store) serviceInts(ctx context.Context, sql string, runIDs []int64) (map[int64]int, error) {
	rows, err := s.db.Query(ctx, sql, runIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64]int{}
	for rows.Next() {
		var id int64
		var v int
		if err := rows.Scan(&id, &v); err != nil {
			return nil, err
		}
		out[id] = v
	}
	return out, rows.Err()
}
