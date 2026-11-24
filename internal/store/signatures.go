package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

var (
	// ErrSignatureNotFound is returned for an unknown signature id.
	ErrSignatureNotFound = fmt.Errorf("signature %w", ErrNotFound)
	// ErrSignatureBuiltin is returned when a write would modify a built-in
	// signature (only enabling or disabling it is allowed).
	ErrSignatureBuiltin = errors.New("built-in signature cannot be modified")
	// ErrSignatureExists is returned when a custom signature id is taken.
	ErrSignatureExists = errors.New("signature id already exists")
)

// SignatureRow is a row of the signatures table.
type SignatureRow struct {
	ID      string
	Name    string
	YAML    string
	Enabled bool
	Builtin bool
}

const signatureCols = `id, name, yaml, enabled, builtin`

func scanSignature(row pgx.Row) (SignatureRow, error) {
	var r SignatureRow
	err := row.Scan(&r.ID, &r.Name, &r.YAML, &r.Enabled, &r.Builtin)
	if errors.Is(err, pgx.ErrNoRows) {
		return r, ErrSignatureNotFound
	}
	return r, err
}

// SyncBuiltinSignatures upserts the built-in signatures. The enabled flag
// set by users is kept, and a custom signature with the same id is left
// untouched.
func (s *Store) SyncBuiltinSignatures(ctx context.Context, sigs []SignatureRow) error {
	return s.InTx(ctx, func(tx *Store) error {
		for _, sg := range sigs {
			if _, err := tx.db.Exec(ctx, `
				INSERT INTO signatures (id, name, yaml, enabled, builtin) VALUES ($1, $2, $3, true, true)
				ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name, yaml = EXCLUDED.yaml
				WHERE signatures.builtin`, sg.ID, sg.Name, sg.YAML); err != nil {
				return fmt.Errorf("signature %s: %w", sg.ID, err)
			}
		}
		return nil
	})
}

// Signatures returns every signature, built-ins first, then by id.
func (s *Store) Signatures(ctx context.Context) ([]SignatureRow, error) {
	rows, err := s.db.Query(ctx, `SELECT `+signatureCols+` FROM signatures ORDER BY builtin DESC, id`)
	if err != nil {
		return nil, err
	}
	return collect(rows, func(r pgx.Rows) (SignatureRow, error) { return scanSignature(r) })
}

// Signature loads one signature.
func (s *Store) Signature(ctx context.Context, id string) (SignatureRow, error) {
	return scanSignature(s.db.QueryRow(ctx, `SELECT `+signatureCols+` FROM signatures WHERE id = $1`, id))
}

// CreateCustomSignature inserts an enabled custom signature; the caller
// validates the YAML first.
func (s *Store) CreateCustomSignature(ctx context.Context, sg SignatureRow) error {
	tag, err := s.db.Exec(ctx, `INSERT INTO signatures (id, name, yaml, enabled, builtin)
		VALUES ($1, $2, $3, true, false) ON CONFLICT (id) DO NOTHING`, sg.ID, sg.Name, sg.YAML)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("%w: %q", ErrSignatureExists, sg.ID)
	}
	return nil
}

// UpdateCustomSignature replaces the name and YAML of a custom signature;
// the id cannot change.
func (s *Store) UpdateCustomSignature(ctx context.Context, id string, sg SignatureRow) error {
	if sg.ID != id {
		return fmt.Errorf("signature id cannot change (%q -> %q)", id, sg.ID)
	}
	tag, err := s.db.Exec(ctx, `UPDATE signatures SET name = $2, yaml = $3 WHERE id = $1 AND NOT builtin`,
		id, sg.Name, sg.YAML)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return s.notFoundOrBuiltin(ctx, id)
	}
	return nil
}

// SetSignatureEnabled enables or disables a signature, built-ins included.
func (s *Store) SetSignatureEnabled(ctx context.Context, id string, enabled bool) error {
	tag, err := s.db.Exec(ctx, `UPDATE signatures SET enabled = $2 WHERE id = $1`, id, enabled)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrSignatureNotFound
	}
	return nil
}

// DeleteCustomSignature removes a custom signature.
func (s *Store) DeleteCustomSignature(ctx context.Context, id string) error {
	tag, err := s.db.Exec(ctx, `DELETE FROM signatures WHERE id = $1 AND NOT builtin`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return s.notFoundOrBuiltin(ctx, id)
	}
	return nil
}

func (s *Store) notFoundOrBuiltin(ctx context.Context, id string) error {
	r, err := s.Signature(ctx, id)
	if err != nil {
		return err
	}
	if r.Builtin {
		return ErrSignatureBuiltin
	}
	return ErrSignatureNotFound
}
