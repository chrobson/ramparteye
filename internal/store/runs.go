package store

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/jackc/pgx/v5"
)

// Run statuses (scan_runs.status).
const (
	RunQueued    = "queued"
	RunRunning   = "running"
	RunPaused    = "paused"
	RunDone      = "done"
	RunFailed    = "failed"
	RunCancelled = "cancelled"
)

// ErrRunNotFound is returned for an unknown run.
var ErrRunNotFound = fmt.Errorf("run %w", ErrNotFound)

// RunInfo is the scheduler's view of a run.
type RunInfo struct {
	ID        int64
	ConfigID  *int64
	Status    string
	StartedAt *time.Time
}

// RunSummary is a run with its progress and result counts.
type RunSummary struct {
	ID           int64
	ConfigID     *int64
	ConfigName   string
	Kind         string // scan | import
	Status       string
	StartedAt    *time.Time
	FinishedAt   *time.Time
	DurationMS   *int64
	ChunksTotal  int
	ChunksDone   int
	ChunksFailed int
	HostsUp      int
	Services     int
	Stopped      bool
	Applied      bool // the diff of the run has been applied
}

// Open reports whether the run can still continue.
func (r RunSummary) Open() bool { return r.Status == RunQueued || r.Status == RunPaused }

const runInfoCols = `id, config_id, status, started_at`

func scanRunInfo(row pgx.Row) (RunInfo, error) {
	var r RunInfo
	err := row.Scan(&r.ID, &r.ConfigID, &r.Status, &r.StartedAt)
	return r, err
}

const runSummaryCols = `r.id, r.config_id, coalesce(c.name, ''), r.kind, r.status, r.started_at, r.finished_at,
	r.duration_ms,
	(SELECT count(*) FROM scan_chunks k WHERE k.run_id = r.id),
	(SELECT count(*) FROM scan_chunks k WHERE k.run_id = r.id AND k.status = 'done'),
	(SELECT count(*) FROM scan_chunks k WHERE k.run_id = r.id AND k.status = 'failed'),
	(SELECT count(*) FROM host_obs h WHERE h.run_id = r.id AND h.up),
	(SELECT count(*) FROM services s WHERE s.run_id = r.id), r.stopped,
	EXISTS (SELECT 1 FROM diff_runs d WHERE d.run_id = r.id)
	FROM scan_runs r LEFT JOIN scan_configs c ON c.id = r.config_id`

func scanRunSummary(row pgx.Row) (RunSummary, error) {
	var r RunSummary
	err := row.Scan(&r.ID, &r.ConfigID, &r.ConfigName, &r.Kind, &r.Status, &r.StartedAt, &r.FinishedAt,
		&r.DurationMS, &r.ChunksTotal, &r.ChunksDone, &r.ChunksFailed, &r.HostsUp, &r.Services, &r.Stopped,
		&r.Applied)
	if errors.Is(err, pgx.ErrNoRows) {
		return r, ErrRunNotFound
	}
	return r, err
}

// CreateRun inserts a queued scan run with one pending chunk per prefix.
func (s *Store) CreateRun(ctx context.Context, configID *int64, chunks []netip.Prefix) (int64, error) {
	var runID int64
	err := s.InTx(ctx, func(tx *Store) error {
		if err := tx.db.QueryRow(ctx, `INSERT INTO scan_runs (config_id, kind, status)
			VALUES ($1, 'scan', 'queued') RETURNING id`, configID).Scan(&runID); err != nil {
			return err
		}
		if len(chunks) == 0 {
			return nil
		}
		rows := make([][]any, len(chunks))
		for i, p := range chunks {
			rows[i] = []any{runID, p.Masked()}
		}
		if _, err := tx.db.CopyFrom(ctx, pgx.Identifier{"scan_chunks"}, []string{"run_id", "cidr"},
			pgx.CopyFromRows(rows)); err != nil {
			return fmt.Errorf("insert chunks: %w", err)
		}
		return nil
	})
	return runID, err
}

// Run returns the summary of one run.
func (s *Store) Run(ctx context.Context, id int64) (RunSummary, error) {
	return scanRunSummary(s.db.QueryRow(ctx, `SELECT `+runSummaryCols+` WHERE r.id = $1`, id))
}

// Runs returns the newest runs first.
func (s *Store) Runs(ctx context.Context, limit int) ([]RunSummary, error) {
	rows, err := s.db.Query(ctx, `SELECT `+runSummaryCols+` ORDER BY r.id DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	return collect(rows, func(r pgx.Rows) (RunSummary, error) { return scanRunSummary(r) })
}

// LatestDoneRun returns the newest finished scan run, or the newest finished
// import when no scan has finished (0 when there is none). A scan whose diff
// is not applied yet is skipped while an older applied one exists.
func (s *Store) LatestDoneRun(ctx context.Context) (int64, error) {
	var id int64
	err := s.db.QueryRow(ctx, `SELECT id FROM scan_runs r WHERE status = 'done'
		ORDER BY (kind = 'scan') DESC, EXISTS (SELECT 1 FROM diff_runs d WHERE d.run_id = r.id) DESC, id DESC
		LIMIT 1`).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, nil
	}
	return id, err
}

// LastRun returns the newest scan run of a profile, or nil.
func (s *Store) LastRun(ctx context.Context, configID int64) (*RunInfo, error) {
	r, err := scanRunInfo(s.db.QueryRow(ctx, `SELECT `+runInfoCols+` FROM scan_runs
		WHERE config_id = $1 AND kind = 'scan' ORDER BY id DESC LIMIT 1`, configID))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &r, nil
}

// OpenRuns lists scan runs that are not finished, not stopped by a user and
// not cancelled (no cancel request), so a cancelled run is never resumed.
func (s *Store) OpenRuns(ctx context.Context) ([]RunInfo, error) {
	rows, err := s.db.Query(ctx, `SELECT `+runInfoCols+` FROM scan_runs r
		WHERE kind = 'scan' AND status IN ('queued', 'running', 'paused') AND NOT stopped
		AND NOT EXISTS (SELECT 1 FROM run_cancel_requests c WHERE c.run_id = r.id) ORDER BY id`)
	if err != nil {
		return nil, err
	}
	return collect(rows, func(r pgx.Rows) (RunInfo, error) { return scanRunInfo(r) })
}

// notFinal matches a run whose status is not final yet: a done, failed or
// cancelled run is never changed again.
const notFinal = ` AND status NOT IN ('done', 'failed', 'cancelled')`

// StartRun marks a run running; started_at keeps the first start. It
// reports false (and changes nothing) when the run already has a final
// status.
func (s *Store) StartRun(ctx context.Context, runID int64) (bool, error) {
	tag, err := s.db.Exec(ctx, `UPDATE scan_runs SET status = 'running',
		started_at = coalesce(started_at, now()), finished_at = NULL WHERE id = $1`+notFinal, runID)
	return tag.RowsAffected() == 1, err
}

// FinishRun sets the final (or paused) status of a run and adds the active
// scanning time of this session to duration_ms, so a run paused by its
// window reports only the time actually spent scanning. A final status is
// never overwritten: it reports false (and changes nothing) when the run
// is already done, failed or cancelled.
func (s *Store) FinishRun(ctx context.Context, runID int64, status string, active time.Duration) (bool, error) {
	tag, err := s.db.Exec(ctx, `UPDATE scan_runs SET status = $2,
		duration_ms = coalesce(duration_ms, 0) + $3,
		finished_at = CASE WHEN $2 IN ('done', 'failed', 'cancelled') THEN now() ELSE NULL END
		WHERE id = $1`+notFinal, runID, status, active.Milliseconds())
	return tag.RowsAffected() == 1, err
}

// ResetRunning is called on startup: chunks left running by a crashed
// process go back to pending and their runs become paused so the scheduler
// resumes them; unfinished runs with a cancel request become cancelled
// instead. It returns the number of chunks reset.
//
// It is global and assumes a single scanning process per database: it must
// run only when no other process executes scans (`serve` calls it once at
// startup). If that assumption is broken, the lease guard of the chunk
// methods keeps it safe: a worker whose chunk was reset and leased again gets
// ErrLeaseLost and its result is dropped.
func (s *Store) ResetRunning(ctx context.Context) (int64, error) {
	var n int64
	err := s.InTx(ctx, func(tx *Store) error {
		tag, err := tx.db.Exec(ctx, `UPDATE scan_chunks SET status = 'pending' WHERE status = 'running'`)
		if err != nil {
			return err
		}
		n = tag.RowsAffected()
		if _, err := tx.db.Exec(ctx, `UPDATE scan_runs r SET status = 'cancelled', finished_at = now()
			WHERE status IN ('queued', 'running', 'paused')
			AND EXISTS (SELECT 1 FROM run_cancel_requests c WHERE c.run_id = r.id)`); err != nil {
			return err
		}
		_, err = tx.db.Exec(ctx, `UPDATE scan_runs SET status = 'paused' WHERE status = 'running'`)
		return err
	})
	return n, err
}

// StopRun marks an unfinished scan run stopped by a user, so the scheduler
// does not resume it; it reports whether the run was open.
func (s *Store) StopRun(ctx context.Context, runID int64) (bool, error) {
	tag, err := s.db.Exec(ctx, `UPDATE scan_runs SET stopped = true
		WHERE id = $1 AND kind = 'scan' AND status IN ('queued', 'running', 'paused')`, runID)
	return tag.RowsAffected() == 1, err
}

// ResumeRun lets the scheduler continue a stopped run; it reports whether
// the run was stopped and resumable.
func (s *Store) ResumeRun(ctx context.Context, runID int64) (bool, error) {
	tag, err := s.db.Exec(ctx, `UPDATE scan_runs SET stopped = false
		WHERE id = $1 AND stopped AND status IN ('queued', 'paused')`, runID)
	return tag.RowsAffected() == 1, err
}

// RequestCancel records a cancel request for each run so every process
// running one of them stops it before its next chunk. by may be nil.
func (s *Store) RequestCancel(ctx context.Context, runIDs []int64, by *int64) error {
	_, err := s.db.Exec(ctx, `INSERT INTO run_cancel_requests (run_id, requested_by)
		SELECT unnest($1::bigint[]), $2 ON CONFLICT (run_id) DO NOTHING`, runIDs, by)
	return err
}

// CancelRequested reports whether a cancel was requested for a run.
func (s *Store) CancelRequested(ctx context.Context, runID int64) (bool, error) {
	var ok bool
	err := s.db.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM run_cancel_requests WHERE run_id = $1)`,
		runID).Scan(&ok)
	return ok, err
}

// CancelOpenRuns records a cancel request (by may be nil) for every
// unfinished scan run, stopped ones included, and marks the runs that are
// not running cancelled at once. A running run is left to the process
// executing it, which honours the request at its next chunk boundary. It
// returns the ids of every run a cancel was requested for and of the runs
// it marked cancelled, both ascending.
func (s *Store) CancelOpenRuns(ctx context.Context, by *int64) (requested, finished []int64, err error) {
	err = s.InTx(ctx, func(tx *Store) error {
		rows, err := tx.db.Query(ctx, `SELECT id, status FROM scan_runs
			WHERE kind = 'scan' AND status IN ('queued', 'running', 'paused') ORDER BY id FOR UPDATE`)
		if err != nil {
			return err
		}
		type open struct {
			id     int64
			status string
		}
		runs, err := collect(rows, func(r pgx.Rows) (open, error) {
			var o open
			err := r.Scan(&o.id, &o.status)
			return o, err
		})
		if err != nil {
			return err
		}
		requested, finished = []int64{}, []int64{}
		for _, o := range runs {
			requested = append(requested, o.id)
			if o.status != RunRunning {
				finished = append(finished, o.id)
			}
		}
		if len(requested) == 0 {
			return nil
		}
		if err := tx.RequestCancel(ctx, requested, by); err != nil {
			return err
		}
		_, err = tx.db.Exec(ctx, `UPDATE scan_runs SET status = 'cancelled', finished_at = now()
			WHERE id = ANY($1)`, finished)
		return err
	})
	if err != nil {
		return nil, nil, err
	}
	return requested, finished, nil
}
