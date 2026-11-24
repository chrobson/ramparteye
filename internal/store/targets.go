package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/chrobson/ramparteye/internal/model"
)

// ErrTargetNotFound is returned when a target id does not exist.
var ErrTargetNotFound = fmt.Errorf("target %w", ErrNotFound)

const targetCols = `id, kind, value, tags`

func scanTarget(r pgx.Rows) (model.Target, error) {
	var t model.Target
	var kind string
	err := r.Scan(&t.ID, &kind, &t.Value, &t.Tags)
	t.Kind = model.TargetKind(kind)
	return t, err
}

func (s *Store) queryTargets(ctx context.Context, sql string, args ...any) ([]model.Target, error) {
	rows, err := s.db.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	return collect(rows, scanTarget)
}

// Targets returns all targets ordered by kind and value, or only those
// carrying tag when tag is not empty.
func (s *Store) Targets(ctx context.Context, tag string) ([]model.Target, error) {
	if tag == "" {
		return s.queryTargets(ctx, `SELECT `+targetCols+` FROM targets ORDER BY kind, value`)
	}
	return s.queryTargets(ctx, `SELECT `+targetCols+` FROM targets WHERE tags @> ARRAY[$1]::text[]
		ORDER BY kind, value`, tag)
}

// TargetsByIDs returns the targets with the given ids; missing ids are
// skipped.
func (s *Store) TargetsByIDs(ctx context.Context, ids []int64) ([]model.Target, error) {
	return s.queryTargets(ctx, `SELECT `+targetCols+` FROM targets WHERE id = ANY($1) ORDER BY id`, ids)
}

// TargetTags returns every tag in use, sorted.
func (s *Store) TargetTags(ctx context.Context) ([]string, error) {
	rows, err := s.db.Query(ctx, `SELECT DISTINCT unnest(tags) AS t FROM targets ORDER BY t`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}

// InsertTargets inserts targets, skipping values that already exist, and
// returns how many were inserted. createdBy may be nil. Run it inside InTx
// when the whole import must be atomic.
func (s *Store) InsertTargets(ctx context.Context, ts []model.Target, createdBy *int64) (int, error) {
	if len(ts) == 0 {
		return 0, nil
	}
	b := &pgx.Batch{}
	for _, t := range ts {
		b.Queue(`INSERT INTO targets (kind, value, tags, created_by) VALUES ($1, $2, $3, $4)
			ON CONFLICT (value) DO NOTHING`, string(t.Kind), t.Value, nonNilSlice(t.Tags), createdBy)
	}
	br := s.db.SendBatch(ctx, b)
	inserted := 0
	for range ts {
		tag, err := br.Exec()
		if err != nil {
			_ = br.Close()
			return inserted, err
		}
		inserted += int(tag.RowsAffected())
	}
	return inserted, br.Close()
}

// UpdateTargetTags replaces the tags of one target.
func (s *Store) UpdateTargetTags(ctx context.Context, id int64, tags []string) error {
	tag, err := s.db.Exec(ctx, `UPDATE targets SET tags = $2 WHERE id = $1`, id, nonNilSlice(tags))
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrTargetNotFound
	}
	return nil
}

// DeleteTarget removes one target and returns its value. Scan profiles keep
// stale ids in target_ids; TargetsByIDs skips them.
func (s *Store) DeleteTarget(ctx context.Context, id int64) (string, error) {
	var value string
	err := s.db.QueryRow(ctx, `DELETE FROM targets WHERE id = $1 RETURNING value`, id).Scan(&value)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrTargetNotFound
	}
	return value, err
}
