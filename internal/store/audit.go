package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// ErrSecretNotFound is returned for an unknown secret name.
var ErrSecretNotFound = fmt.Errorf("secret %w", ErrNotFound)

// AuditEntry is one audit_log row with the actor's login resolved.
type AuditEntry struct {
	ID      int64
	At      time.Time
	UserID  *int64
	Login   string // "" when there is no actor
	Action  string
	Entity  string
	Details string // JSON object
}

// InsertAudit appends an audit_log entry. userID may be nil (failed login,
// system action); details is marshalled to JSON (nil = {}).
func (s *Store) InsertAudit(ctx context.Context, userID *int64, action, entity string, details any) error {
	if details == nil {
		details = map[string]any{}
	}
	b, err := json.Marshal(details)
	if err != nil {
		return fmt.Errorf("audit details: %w", err)
	}
	_, err = s.db.Exec(ctx, `INSERT INTO audit_log (user_id, action, entity, details) VALUES ($1, $2, $3, $4)`,
		userID, action, entity, b)
	return err
}

// AuditEntries returns the newest audit entries first.
func (s *Store) AuditEntries(ctx context.Context, limit int) ([]AuditEntry, error) {
	rows, err := s.db.Query(ctx, `SELECT a.id, a.at, a.user_id, coalesce(u.login, ''), a.action, a.entity, a.details::text
		FROM audit_log a LEFT JOIN users u ON u.id = a.user_id
		ORDER BY a.at DESC, a.id DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	return collect(rows, scanAuditEntry)
}

// AuditFilter selects a page of audit entries, newest first.
type AuditFilter struct {
	Action string // "" = every action
	Limit  int
	Offset int
}

// AuditQuery returns one page of audit entries, newest first.
func (s *Store) AuditQuery(ctx context.Context, f AuditFilter) ([]AuditEntry, error) {
	rows, err := s.db.Query(ctx, `SELECT a.id, a.at, a.user_id, coalesce(u.login, ''), a.action, a.entity, a.details::text
		FROM audit_log a LEFT JOIN users u ON u.id = a.user_id
		WHERE $1 = '' OR a.action = $1
		ORDER BY a.at DESC, a.id DESC LIMIT $2 OFFSET $3`, f.Action, f.Limit, f.Offset)
	if err != nil {
		return nil, err
	}
	return collect(rows, scanAuditEntry)
}

// AuditActions returns every distinct audit action, sorted.
func (s *Store) AuditActions(ctx context.Context) ([]string, error) {
	rows, err := s.db.Query(ctx, `SELECT DISTINCT action FROM audit_log ORDER BY action`)
	if err != nil {
		return nil, err
	}
	return collect(rows, func(r pgx.Rows) (string, error) {
		var a string
		err := r.Scan(&a)
		return a, err
	})
}

func scanAuditEntry(r pgx.Rows) (AuditEntry, error) {
	var e AuditEntry
	err := r.Scan(&e.ID, &e.At, &e.UserID, &e.Login, &e.Action, &e.Entity, &e.Details)
	return e, err
}

// PutSecret upserts an already encrypted secret.
func (s *Store) PutSecret(ctx context.Context, name string, enc []byte) error {
	_, err := s.db.Exec(ctx, `INSERT INTO secrets (name, value_enc) VALUES ($1, $2)
		ON CONFLICT (name) DO UPDATE SET value_enc = EXCLUDED.value_enc`, name, enc)
	if err != nil {
		return fmt.Errorf("put secret %s: %w", name, sanitize(err))
	}
	return nil
}

// Secret returns an encrypted secret or ErrSecretNotFound.
func (s *Store) Secret(ctx context.Context, name string) ([]byte, error) {
	var enc []byte
	err := s.db.QueryRow(ctx, `SELECT value_enc FROM secrets WHERE name = $1`, name).Scan(&enc)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrSecretNotFound
	}
	return enc, err
}
