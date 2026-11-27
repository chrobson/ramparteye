package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// NotifyConfig is the single notify_config row: the webhook notification
// settings edited in Settings. URLEnc and SecretEnc are sealed (nil = none);
// Endpoint is the scheme and host of the webhook URL.
type NotifyConfig struct {
	Enabled      bool
	URLEnc       []byte
	Endpoint     string
	Format       string // json | slack
	SecretEnc    []byte
	OnlyChanges  bool
	NotifyFailed bool
	BaseURL      string
	// ClearURL removes the stored URL and endpoint on save (URLEnc must be
	// nil); ClearSecret removes the stored secret (SecretEnc must be nil).
	ClearURL    bool
	ClearSecret bool
	UpdatedAt   time.Time
}

// NotifyDelivery is one recorded webhook delivery.
type NotifyDelivery struct {
	ID       int64
	RunID    *int64 // nil for a test notification
	At       time.Time
	Trigger  string // auto | test
	Event    string // scan.finished | scan.failed | test
	Endpoint string // scheme://host[:port] of the webhook URL
	Attempts int
	Status   *int // last HTTP status (nil = no response)
	OK       bool
	Error    string
}

// maxNotifyError bounds notify_deliveries.error.
const maxNotifyError = 500

// NotifyConfig loads the webhook notification settings.
func (s *Store) NotifyConfig(ctx context.Context) (NotifyConfig, error) {
	var c NotifyConfig
	err := s.db.QueryRow(ctx, `SELECT enabled, url_enc, endpoint, format, secret_enc, only_changes,
		notify_failed, base_url, updated_at FROM notify_config`).
		Scan(&c.Enabled, &c.URLEnc, &c.Endpoint, &c.Format, &c.SecretEnc, &c.OnlyChanges, &c.NotifyFailed,
			&c.BaseURL, &c.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return NotifyConfig{}, fmt.Errorf("notification config row: %w", ErrNotFound)
	}
	return c, err
}

// SaveNotifyConfig replaces the webhook notification settings. A nil URLEnc
// keeps the stored URL and endpoint unless ClearURL is set; a nil SecretEnc
// keeps the stored secret unless ClearSecret is set. Errors never carry the
// sealed values.
func (s *Store) SaveNotifyConfig(ctx context.Context, c NotifyConfig) error {
	tag, err := s.db.Exec(ctx, `UPDATE notify_config SET enabled = $1,
		url_enc = CASE WHEN $9 THEN NULL ELSE coalesce($2, url_enc) END,
		endpoint = CASE WHEN $9 THEN '' WHEN $2::bytea IS NULL THEN endpoint ELSE $3 END,
		format = $4,
		secret_enc = CASE WHEN $10 THEN NULL ELSE coalesce($5, secret_enc) END,
		only_changes = $6, notify_failed = $7, base_url = $8, updated_at = now()`,
		c.Enabled, c.URLEnc, c.Endpoint, c.Format, c.SecretEnc, c.OnlyChanges, c.NotifyFailed, c.BaseURL,
		c.ClearURL, c.ClearSecret)
	if err != nil {
		return fmt.Errorf("save notification config: %w", sanitize(err))
	}
	if tag.RowsAffected() != 1 {
		return fmt.Errorf("save notification config row: %w", ErrNotFound)
	}
	return nil
}

// RecordNotifyDelivery stores a delivery. A RunID naming no run is stored
// as NULL; the error text is cut to its column limit.
func (s *Store) RecordNotifyDelivery(ctx context.Context, d NotifyDelivery) error {
	_, err := s.db.Exec(ctx, `INSERT INTO notify_deliveries
		(run_id, trigger, event, endpoint, attempts, status, ok, error)
		VALUES ((SELECT id FROM scan_runs WHERE id = $1::bigint), $2, $3, $4, $5, $6, $7, left($8, $9))`,
		d.RunID, d.Trigger, d.Event, d.Endpoint, d.Attempts, d.Status, d.OK, d.Error, maxNotifyError)
	if err != nil {
		return fmt.Errorf("record notification: %w", sanitize(err))
	}
	return nil
}

// NotifyDeliveries returns the latest deliveries, newest first.
func (s *Store) NotifyDeliveries(ctx context.Context, limit int) ([]NotifyDelivery, error) {
	rows, err := s.db.Query(ctx, `SELECT id, run_id, at, trigger, event, endpoint, attempts, status, ok, error
		FROM notify_deliveries ORDER BY at DESC, id DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	return collect(rows, func(r pgx.Rows) (NotifyDelivery, error) {
		var d NotifyDelivery
		err := r.Scan(&d.ID, &d.RunID, &d.At, &d.Trigger, &d.Event, &d.Endpoint, &d.Attempts, &d.Status,
			&d.OK, &d.Error)
		return d, err
	})
}
