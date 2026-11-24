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

// Signature sources (signatures.source).
const (
	SourceBuiltin = "builtin"
	SourceCustom  = "custom"
	SourceNuclei  = "nuclei"
)

// SignatureRow is a row of the signatures table.
type SignatureRow struct {
	ID        string
	Name      string
	YAML      string
	Enabled   bool
	Source    string // SourceBuiltin | SourceCustom | SourceNuclei
	PathProbe bool   // the signature sends extra requests
}

// IsBuiltin reports whether the row is a built-in signature.
func (r SignatureRow) IsBuiltin() bool { return r.Source == SourceBuiltin }

const signatureCols = `id, name, yaml, enabled, source, path_probe`

func scanSignature(row pgx.Row) (SignatureRow, error) {
	var r SignatureRow
	err := row.Scan(&r.ID, &r.Name, &r.YAML, &r.Enabled, &r.Source, &r.PathProbe)
	if errors.Is(err, pgx.ErrNoRows) {
		return r, ErrSignatureNotFound
	}
	return r, err
}

// SyncBuiltinSignatures makes the built-in rows match sigs (Source and
// Enabled of the rows are ignored): new ones are inserted enabled, existing
// ones get the new name, YAML and path probe flag but keep the enabled flag
// set by users, and built-in rows no longer in sigs are deleted. A custom
// or nuclei signature with the id of a built-in is left untouched; those
// ids are returned as collisions.
func (s *Store) SyncBuiltinSignatures(ctx context.Context, sigs []SignatureRow) ([]string, error) {
	var collisions []string
	err := s.InTx(ctx, func(tx *Store) error {
		collisions = nil
		ids := make([]string, 0, len(sigs))
		for _, sg := range sigs {
			ids = append(ids, sg.ID)
			var source string
			err := tx.db.QueryRow(ctx, `
				INSERT INTO signatures (id, name, yaml, enabled, source, path_probe)
				VALUES ($1, $2, $3, true, 'builtin', $4)
				ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name, yaml = EXCLUDED.yaml,
					path_probe = EXCLUDED.path_probe
				WHERE signatures.source = 'builtin'
				RETURNING source`, sg.ID, sg.Name, sg.YAML, sg.PathProbe).Scan(&source)
			switch {
			case errors.Is(err, pgx.ErrNoRows): // conflict with a non-built-in row
				collisions = append(collisions, sg.ID)
			case err != nil:
				return fmt.Errorf("signature %s: %w", sg.ID, err)
			}
		}
		if _, err := tx.db.Exec(ctx, `DELETE FROM signatures WHERE source = 'builtin' AND NOT (id = ANY($1))`, ids); err != nil {
			return fmt.Errorf("delete dropped built-in signatures: %w", err)
		}
		return nil
	})
	return collisions, err
}

// Signatures returns every signature, built-ins first, then by id.
func (s *Store) Signatures(ctx context.Context) ([]SignatureRow, error) {
	rows, err := s.db.Query(ctx, `SELECT `+signatureCols+` FROM signatures
		ORDER BY source = 'builtin' DESC, id`)
	if err != nil {
		return nil, err
	}
	return collect(rows, func(r pgx.Rows) (SignatureRow, error) { return scanSignature(r) })
}

// Signature loads one signature.
func (s *Store) Signature(ctx context.Context, id string) (SignatureRow, error) {
	return scanSignature(s.db.QueryRow(ctx, `SELECT `+signatureCols+` FROM signatures WHERE id = $1`, id))
}

// CreateCustomSignature inserts a custom or nuclei signature (an empty
// Source means custom) with its Enabled and PathProbe flags; the caller
// validates the YAML first. A built-in Source is refused.
func (s *Store) CreateCustomSignature(ctx context.Context, sg SignatureRow) error {
	switch sg.Source {
	case "":
		sg.Source = SourceCustom
	case SourceBuiltin:
		return fmt.Errorf("%w: %q", ErrSignatureBuiltin, sg.ID)
	}
	tag, err := s.db.Exec(ctx, `INSERT INTO signatures (id, name, yaml, enabled, source, path_probe)
		VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (id) DO NOTHING`,
		sg.ID, sg.Name, sg.YAML, sg.Enabled, sg.Source, sg.PathProbe)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("%w: %q", ErrSignatureExists, sg.ID)
	}
	return nil
}

// UpdateCustomSignature replaces the name, YAML and path probe flag of a
// custom or nuclei signature; the id, source and enabled flag do not change.
func (s *Store) UpdateCustomSignature(ctx context.Context, id string, sg SignatureRow) error {
	if sg.ID != id {
		return fmt.Errorf("signature id cannot change (%q -> %q)", id, sg.ID)
	}
	tag, err := s.db.Exec(ctx, `UPDATE signatures SET name = $2, yaml = $3, path_probe = $4
		WHERE id = $1 AND source <> 'builtin'`, id, sg.Name, sg.YAML, sg.PathProbe)
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

// DeleteCustomSignature removes a custom or nuclei signature.
func (s *Store) DeleteCustomSignature(ctx context.Context, id string) error {
	tag, err := s.db.Exec(ctx, `DELETE FROM signatures WHERE id = $1 AND source <> 'builtin'`, id)
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
	if r.IsBuiltin() {
		return ErrSignatureBuiltin
	}
	return ErrSignatureNotFound
}
