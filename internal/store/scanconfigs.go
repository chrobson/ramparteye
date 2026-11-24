package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/chrobson/ramparteye/internal/model"
)

var (
	// ErrScanConfigNotFound is returned for an unknown scan profile.
	ErrScanConfigNotFound = fmt.Errorf("scan profile %w", ErrNotFound)
	// ErrScanConfigNameTaken is returned when a profile name is in use.
	ErrScanConfigNameTaken = errors.New("scan profile name already taken")
	// ErrScanConfigBusy is returned when deleting a profile with an
	// unfinished run.
	ErrScanConfigBusy = errors.New("scan profile has an unfinished run")
)

// ScanConfig is a scan profile (scan_configs row). Window times are offsets
// from local midnight; WindowEnd may be earlier than WindowStart (the
// window crosses midnight).
type ScanConfig struct {
	ID           int64
	Name         string
	TargetIDs    []int64 // empty = every target
	TopPorts     int
	MaxRate      int // packets/s for the whole run
	Workers      int
	WindowStart  *time.Duration
	WindowEnd    *time.Duration
	EveryMinutes *int // nil = manual only
	Enabled      bool
	// PortProfile is auto, top, list or all; "" is stored as auto.
	PortProfile   string
	Ports         string // explicit TCP port list for the list profile
	ExtraPorts    bool   // second pass over common infrastructure ports (top profile)
	ExtraPortList string // additional ports of that pass
}

// HasWindow reports whether the profile restricts scanning to a window.
func (c ScanConfig) HasWindow() bool { return c.WindowStart != nil && c.WindowEnd != nil }

const configCols = `id, name, target_ids, top_ports, max_rate, workers, window_start, window_end,
	every_minutes, enabled, port_profile, ports, extra_ports, extra_port_list`

func scanConfig(row pgx.Row) (ScanConfig, error) {
	var c ScanConfig
	var ws, we pgtype.Time
	var every pgtype.Int4
	err := row.Scan(&c.ID, &c.Name, &c.TargetIDs, &c.TopPorts, &c.MaxRate, &c.Workers, &ws, &we, &every,
		&c.Enabled, &c.PortProfile, &c.Ports, &c.ExtraPorts, &c.ExtraPortList)
	if errors.Is(err, pgx.ErrNoRows) {
		return c, ErrScanConfigNotFound
	}
	if err != nil {
		return c, err
	}
	c.WindowStart, c.WindowEnd = fromTime(ws), fromTime(we)
	if every.Valid {
		n := int(every.Int32)
		c.EveryMinutes = &n
	}
	return c, nil
}

func fromTime(t pgtype.Time) *time.Duration {
	if !t.Valid {
		return nil
	}
	d := time.Duration(t.Microseconds) * time.Microsecond
	return &d
}

func toTime(d *time.Duration) pgtype.Time {
	if d == nil {
		return pgtype.Time{}
	}
	return pgtype.Time{Microseconds: d.Microseconds(), Valid: true}
}

func configArgs(c ScanConfig) []any {
	profile := c.PortProfile
	if profile == "" {
		profile = "auto"
	}
	return []any{c.Name, nonNilSlice(c.TargetIDs), c.TopPorts, c.MaxRate, c.Workers,
		toTime(c.WindowStart), toTime(c.WindowEnd), c.EveryMinutes, c.Enabled,
		profile, c.Ports, c.ExtraPorts, c.ExtraPortList}
}

func configWriteErr(err error) error {
	if pgCode(err) == codeUniqueViolation {
		return ErrScanConfigNameTaken
	}
	return err
}

// ScanConfigs lists every scan profile.
func (s *Store) ScanConfigs(ctx context.Context) ([]ScanConfig, error) {
	rows, err := s.db.Query(ctx, `SELECT `+configCols+` FROM scan_configs ORDER BY id`)
	if err != nil {
		return nil, err
	}
	return collect(rows, func(r pgx.Rows) (ScanConfig, error) { return scanConfig(r) })
}

// ScanConfig returns one scan profile.
func (s *Store) ScanConfig(ctx context.Context, id int64) (ScanConfig, error) {
	return scanConfig(s.db.QueryRow(ctx, `SELECT `+configCols+` FROM scan_configs WHERE id = $1`, id))
}

// CreateScanConfig inserts a profile (c.ID is ignored) and returns its id.
func (s *Store) CreateScanConfig(ctx context.Context, c ScanConfig) (int64, error) {
	var id int64
	err := s.db.QueryRow(ctx, `INSERT INTO scan_configs (name, target_ids, top_ports, max_rate, workers,
		window_start, window_end, every_minutes, enabled, port_profile, ports, extra_ports, extra_port_list)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13) RETURNING id`,
		configArgs(c)...).Scan(&id)
	return id, configWriteErr(err)
}

// UpdateScanConfig replaces the profile with id c.ID.
func (s *Store) UpdateScanConfig(ctx context.Context, c ScanConfig) error {
	tag, err := s.db.Exec(ctx, `UPDATE scan_configs SET name = $2, target_ids = $3, top_ports = $4,
		max_rate = $5, workers = $6, window_start = $7, window_end = $8, every_minutes = $9, enabled = $10,
		port_profile = $11, ports = $12, extra_ports = $13, extra_port_list = $14 WHERE id = $1`,
		append([]any{c.ID}, configArgs(c)...)...)
	if err != nil {
		return configWriteErr(err)
	}
	if tag.RowsAffected() == 0 {
		return ErrScanConfigNotFound
	}
	return nil
}

// DeleteScanConfig removes a profile. Its finished runs keep their results
// and lose the reference; a profile with an unfinished run is refused.
func (s *Store) DeleteScanConfig(ctx context.Context, id int64) error {
	return s.InTx(ctx, func(tx *Store) error {
		if _, err := tx.db.Exec(ctx, `UPDATE scan_runs SET config_id = NULL
			WHERE config_id = $1 AND status IN ('done', 'failed', 'cancelled')`, id); err != nil {
			return err
		}
		tag, err := tx.db.Exec(ctx, `DELETE FROM scan_configs WHERE id = $1`, id)
		if pgCode(err) == codeForeignKeyViolation {
			return ErrScanConfigBusy
		}
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrScanConfigNotFound
		}
		return nil
	})
}

// EnsureDefaultScanConfig creates a manual profile named name covering
// every target when no profile exists, and reports whether it did.
func (s *Store) EnsureDefaultScanConfig(ctx context.Context, name string) (bool, error) {
	tag, err := s.db.Exec(ctx, `INSERT INTO scan_configs (name, target_ids)
		SELECT $1, '{}' WHERE NOT EXISTS (SELECT 1 FROM scan_configs)`, name)
	return tag.RowsAffected() == 1, err
}

// ScanTargets returns the targets of a profile: the given ids, or every
// target when ids is empty.
func (s *Store) ScanTargets(ctx context.Context, ids []int64) ([]model.Target, error) {
	if len(ids) == 0 {
		return s.queryTargets(ctx, `SELECT `+targetCols+` FROM targets ORDER BY id`)
	}
	return s.TargetsByIDs(ctx, ids)
}
