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
	ID         int64
	RunID      *int64
	At         time.Time
	Trigger    string // auto | manual | cli
	Endpoint   string // import-scan | reimport-scan
	Findings   int
	Added      int
	Closed     int
	TestID     *int64
	OK         bool
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

// RecordDojoPush stores a push attempt.
func (s *Store) RecordDojoPush(ctx context.Context, p DojoPush) error {
	stats := p.Statistics
	if len(stats) == 0 {
		stats = json.RawMessage("{}")
	}
	_, err := s.db.Exec(ctx, `INSERT INTO dojo_pushes
		(run_id, trigger, endpoint, findings, added, closed, test_id, ok, error, statistics)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		p.RunID, p.Trigger, p.Endpoint, p.Findings, p.Added, p.Closed, p.TestID, p.OK, p.Error, []byte(stats))
	return err
}

// DojoPushes returns the latest push attempts, newest first.
func (s *Store) DojoPushes(ctx context.Context, limit int) ([]DojoPush, error) {
	rows, err := s.db.Query(ctx, `SELECT id, run_id, at, trigger, endpoint, findings, added, closed, test_id,
		ok, error, statistics FROM dojo_pushes ORDER BY at DESC, id DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	return collect(rows, func(r pgx.Rows) (DojoPush, error) {
		var p DojoPush
		var stats []byte
		err := r.Scan(&p.ID, &p.RunID, &p.At, &p.Trigger, &p.Endpoint, &p.Findings, &p.Added, &p.Closed,
			&p.TestID, &p.OK, &p.Error, &stats)
		p.Statistics = stats
		return p, err
	})
}
