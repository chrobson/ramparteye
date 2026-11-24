package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// DojoConfig is the single dojo_config row: the DefectDojo connection
// edited in Settings. TokenEnc is the sealed API token (nil = none).
type DojoConfig struct {
	URL          string
	TokenEnc     []byte
	ProductType  string
	Product      string
	Engagement   string
	AutoPush     bool
	CloseMissing bool
	ManagedByEnv bool
	// ClearToken removes the stored token on save (TokenEnc must be nil).
	ClearToken bool
	UpdatedAt  time.Time
}

// DojoPush is one recorded DefectDojo push attempt.
type DojoPush struct {
	ID       int64
	RunID    *int64
	At       time.Time
	Trigger  string // auto | manual | cli
	Endpoint string // import-scan | reimport-scan
	Findings int
	Added    int
	Closed   int
	TestID   *int64
	OK       bool
	// Skipped marks an automatic push that was not sent because a newer
	// run of the same profile had already been pushed.
	Skipped    bool
	Error      string
	Statistics json.RawMessage
}

// DojoConfig loads the DefectDojo configuration.
func (s *Store) DojoConfig(ctx context.Context) (DojoConfig, error) {
	var c DojoConfig
	err := s.db.QueryRow(ctx, `SELECT url, token_enc, product_type, product, engagement, auto_push,
		close_missing, managed_by_env, updated_at FROM dojo_config`).
		Scan(&c.URL, &c.TokenEnc, &c.ProductType, &c.Product, &c.Engagement, &c.AutoPush,
			&c.CloseMissing, &c.ManagedByEnv, &c.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return DojoConfig{}, fmt.Errorf("DefectDojo config row: %w", ErrNotFound)
	}
	return c, err
}

// SaveDojoConfig replaces the DefectDojo configuration. A nil TokenEnc keeps
// the stored token unless ClearToken is set. Errors never carry the token.
func (s *Store) SaveDojoConfig(ctx context.Context, c DojoConfig) error {
	tag, err := s.db.Exec(ctx, `UPDATE dojo_config SET url = $1, token_enc = CASE WHEN $9 THEN NULL ELSE coalesce($2, token_enc) END,
		product_type = $3, product = $4, engagement = $5, auto_push = $6, close_missing = $7,
		managed_by_env = $8, updated_at = now()`,
		c.URL, c.TokenEnc, c.ProductType, c.Product, c.Engagement, c.AutoPush, c.CloseMissing, c.ManagedByEnv, c.ClearToken)
	if err != nil {
		return fmt.Errorf("save DefectDojo config: %w", sanitize(err))
	}
	if tag.RowsAffected() != 1 {
		return fmt.Errorf("save DefectDojo config row: %w", ErrNotFound)
	}
	return nil
}

// RecordDojoPush stores a push attempt. A RunID naming no run is stored as
// NULL, so a failed push of an unknown run is still recorded.
func (s *Store) RecordDojoPush(ctx context.Context, p DojoPush) error {
	stats := p.Statistics
	if len(stats) == 0 {
		stats = json.RawMessage("{}")
	}
	_, err := s.db.Exec(ctx, `INSERT INTO dojo_pushes
		(run_id, trigger, endpoint, findings, added, closed, test_id, ok, skipped, error, statistics)
		VALUES ((SELECT id FROM scan_runs WHERE id = $1::bigint), $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
		p.RunID, p.Trigger, p.Endpoint, p.Findings, p.Added, p.Closed, p.TestID, p.OK, p.Skipped, p.Error, []byte(stats))
	return err
}

const dojoPushCols = `id, run_id, at, trigger, endpoint, findings, added, closed, test_id, ok, skipped, error,
	statistics`

func scanDojoPush(r pgx.Row) (DojoPush, error) {
	var p DojoPush
	var stats []byte
	err := r.Scan(&p.ID, &p.RunID, &p.At, &p.Trigger, &p.Endpoint, &p.Findings, &p.Added, &p.Closed,
		&p.TestID, &p.OK, &p.Skipped, &p.Error, &stats)
	p.Statistics = stats
	return p, err
}

// DojoPushes returns the latest push attempts, newest first.
func (s *Store) DojoPushes(ctx context.Context, limit int) ([]DojoPush, error) {
	rows, err := s.db.Query(ctx, `SELECT `+dojoPushCols+` FROM dojo_pushes ORDER BY at DESC, id DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	return collect(rows, func(r pgx.Rows) (DojoPush, error) { return scanDojoPush(r) })
}

// LatestDojoPush returns the newest push attempt that was not skipped, or
// with okOnly the newest successful one (nil = none).
func (s *Store) LatestDojoPush(ctx context.Context, okOnly bool) (*DojoPush, error) {
	p, err := scanDojoPush(s.db.QueryRow(ctx, `SELECT `+dojoPushCols+` FROM dojo_pushes
		WHERE NOT skipped AND (ok OR NOT $1) ORDER BY at DESC, id DESC LIMIT 1`, okOnly))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &p, nil
}

// DojoRun is a finished run with everything a DefectDojo push needs: the
// full service inventory of the run, the annotations of its hosts and the
// scan profile that names the DefectDojo test.
type DojoRun struct {
	Run         ExportRun
	ProfileName string // "" = no profile (ad-hoc scan or import)
	Services    []ExportService
	Annotations []Annotation
}

// DojoRun loads run runID, or the latest finished run when runID is 0. It
// returns ErrRunNotFound unless the run is done.
func (s *Store) DojoRun(ctx context.Context, runID int64) (DojoRun, error) {
	var (
		out DojoRun
		err error
	)
	if runID == 0 {
		out.Run, err = s.LatestExportRun(ctx)
	} else {
		out.Run, err = s.ExportRunByID(ctx, runID)
	}
	if err != nil {
		return DojoRun{}, err
	}
	if err := s.db.QueryRow(ctx, `SELECT coalesce(c.name, '')
		FROM scan_runs r LEFT JOIN scan_configs c ON c.id = r.config_id WHERE r.id = $1`, out.Run.ID).
		Scan(&out.ProfileName); err != nil {
		return DojoRun{}, err
	}
	if out.Services, err = s.ExportServices(ctx, out.Run.ID); err != nil {
		return DojoRun{}, err
	}
	rows, err := s.db.Query(ctx, `SELECT `+annotationCols+` FROM annotations
		WHERE ip IN (SELECT ip FROM services WHERE run_id = $1) ORDER BY ip, port, proto, vhost`, out.Run.ID)
	if err != nil {
		return DojoRun{}, err
	}
	if out.Annotations, err = collect(rows, func(r pgx.Rows) (Annotation, error) { return scanAnnotation(r) }); err != nil {
		return DojoRun{}, err
	}
	return out, nil
}

// DojoLastPush is the push history of the scan profile of a run.
type DojoLastPush struct {
	// RunID is the newest run successfully pushed (nil = never pushed).
	RunID *int64
	// Findings is the finding count of the latest successful push.
	Findings *int
}

// DojoLastPush returns the successful push history of the profile of run
// runID; runs without a profile (ad-hoc scans, imports) share one history.
func (s *Store) DojoLastPush(ctx context.Context, runID int64) (DojoLastPush, error) {
	var out DojoLastPush
	err := s.db.QueryRow(ctx, `WITH pushed AS (
			SELECT p.id, p.at, p.run_id, p.findings FROM dojo_pushes p JOIN scan_runs r ON r.id = p.run_id
			WHERE p.ok AND NOT p.skipped
			  AND r.config_id IS NOT DISTINCT FROM (SELECT config_id FROM scan_runs WHERE id = $1))
		SELECT (SELECT max(run_id) FROM pushed),
		       (SELECT findings FROM pushed ORDER BY at DESC, id DESC LIMIT 1)`, runID).
		Scan(&out.RunID, &out.Findings)
	return out, err
}
