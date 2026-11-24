//go:build integration

package store_test

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"testing"

	"github.com/ctx42/testing/pkg/must"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/chrobson/ramparteye/internal/store"
	"github.com/chrobson/ramparteye/internal/testdb"
)

var ctx = context.Background()

func newStore(t *testing.T) (*store.Store, *pgxpool.Pool) {
	t.Helper()
	pool := testdb.New(t)
	return store.New(pool), pool
}

// insertRun adds a finished run of the given kind and returns its id.
func insertRun(t *testing.T, pool *pgxpool.Pool, kind, status string) int64 {
	t.Helper()
	var id int64
	must.Nil(pool.QueryRow(ctx, `INSERT INTO scan_runs (kind, status, started_at, finished_at)
		VALUES ($1, $2, now(), now()) RETURNING id`, kind, status).Scan(&id))
	return id
}

// insertService adds a service row and returns its id.
func insertService(t *testing.T, pool *pgxpool.Pool, runID int64, ip string, port int) int64 {
	t.Helper()
	var id int64
	must.Nil(pool.QueryRow(ctx, `INSERT INTO services (run_id, ip, port, proto) VALUES ($1, $2::inet, $3, 'tcp')
		RETURNING id`, runID, ip, port).Scan(&id))
	return id
}

func addr(s string) netip.Addr { return netip.MustParseAddr(s) }

// errorText renders err with every field of a wrapped PostgreSQL error
// (Detail, Where, ...), where a failing row would echo stored values.
func errorText(err error) string {
	text := err.Error()
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		text += fmt.Sprintf(" %+v", *pe)
	}
	return text
}
