// Package store is the PostgreSQL persistence of RampartEye: plain pgx
// queries, one file per area.
package store

import (
	"context"
	"errors"
	"fmt"
	"net/netip"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// DBTX is satisfied by *pgxpool.Pool, *pgx.Conn and pgx.Tx.
type DBTX interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	SendBatch(ctx context.Context, b *pgx.Batch) pgx.BatchResults
	CopyFrom(ctx context.Context, table pgx.Identifier, cols []string, src pgx.CopyFromSource) (int64, error)
	Begin(ctx context.Context) (pgx.Tx, error)
}

// ErrNotFound is returned when a row a method needs does not exist.
var ErrNotFound = errors.New("not found")

// Store runs queries on a pool or, inside InTx, on one transaction.
type Store struct {
	db DBTX
}

// New returns a Store on db.
func New(db DBTX) *Store { return &Store{db: db} }

// InTx runs fn in a transaction (a savepoint when s is already inside one)
// and commits when fn returns nil.
func (s *Store) InTx(ctx context.Context, fn func(tx *Store) error) error {
	return pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error { return fn(&Store{db: tx}) })
}

// sanitize drops everything from a PostgreSQL error that may echo stored
// values (the failing row in Detail, Where, Hint), so errors from writes of
// password hashes or sealed tokens never carry them. Code, message and
// constraint name stay for errors.As checks.
func sanitize(err error) error {
	var pe *pgconn.PgError
	if !errors.As(err, &pe) {
		return err
	}
	return &pgconn.PgError{
		Severity:       pe.Severity,
		Code:           pe.Code,
		Message:        pe.Message,
		SchemaName:     pe.SchemaName,
		TableName:      pe.TableName,
		ColumnName:     pe.ColumnName,
		ConstraintName: pe.ConstraintName,
	}
}

// pgCode returns the SQLSTATE of a PostgreSQL error, or "".
func pgCode(err error) string {
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		return pe.Code
	}
	return ""
}

const (
	codeUniqueViolation     = "23505"
	codeForeignKeyViolation = "23503"
)

// Inet values are passed and read as text (host(ip)) so netip.Addr
// round-trips without depending on pgx's inet codec.
func parseAddr(s string) (netip.Addr, error) {
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("parse ip %q: %w", s, err)
	}
	return a.Unmap(), nil
}

func nonNilMap[V any](m map[string]V) map[string]V {
	if m == nil {
		return map[string]V{}
	}
	return m
}

func nonNilSlice[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

// collect scans every row with scan.
func collect[T any](rows pgx.Rows, scan func(pgx.Rows) (T, error)) ([]T, error) {
	defer rows.Close()
	var out []T
	for rows.Next() {
		v, err := scan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
