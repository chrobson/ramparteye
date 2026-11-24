//go:build integration

package db_test

import (
	"context"
	"os"
	"sync"
	"testing"

	"github.com/ctx42/testing/pkg/assert"

	"github.com/chrobson/ramparteye/internal/db"
	"github.com/chrobson/ramparteye/internal/testdb"
)

func TestMigrateIdempotent(t *testing.T) {
	pool := testdb.NewEmpty(t)
	ctx := context.Background()

	first, err := db.Migrate(ctx, pool)
	assert.NoError(t, err)
	assert.True(t, len(first) > 0)
	assert.Equal(t, "0001_schema", first[0])

	second, err := db.Migrate(ctx, pool)
	assert.NoError(t, err)
	assert.Len(t, 0, second)

	var n int
	assert.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM schema_migrations`).Scan(&n))
	assert.Equal(t, len(first), n)
}

// The app starting while `ramparteye migrate` runs must not collide on
// CREATE TABLE: concurrent callers wait on an advisory lock.
func TestMigrateConcurrent(t *testing.T) {
	pool := testdb.NewEmpty(t)
	ctx := context.Background()

	var wg sync.WaitGroup
	errs := make([]error, 4)
	applied := make([][]string, 4)
	for i := range errs {
		wg.Go(func() { applied[i], errs[i] = db.Migrate(ctx, pool) })
	}
	wg.Wait()

	total := 0
	for i, err := range errs {
		assert.NoError(t, err)
		total += len(applied[i])
	}
	var n int
	assert.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM schema_migrations`).Scan(&n))
	assert.Equal(t, n, total)
}

func TestPgTDEEnabled(t *testing.T) {
	pool := testdb.New(t)
	if os.Getenv("RAMPART_TEST_EXPECT_TDE") != "1" {
		t.Skip("RAMPART_TEST_EXPECT_TDE not set")
	}
	ctx := context.Background()

	var ext []string
	rows, err := pool.Query(ctx, `SELECT extname FROM pg_extension`)
	assert.NoError(t, err)
	for rows.Next() {
		var s string
		assert.NoError(t, rows.Scan(&s))
		ext = append(ext, s)
	}
	assert.NoError(t, rows.Err())
	assert.Has(t, "pg_tde", ext)

	// Application tables use the encrypted access method.
	var am string
	assert.NoError(t, pool.QueryRow(ctx, `SELECT a.amname FROM pg_class c JOIN pg_am a ON a.oid = c.relam
		WHERE c.oid = 'users'::regclass`).Scan(&am))
	assert.Equal(t, "tde_heap", am)
}

func TestStatisticsDisabledForTextColumns(t *testing.T) {
	pool := testdb.New(t)
	ctx := context.Background()

	// pg_statistic is outside pg_tde: no text-like column may keep samples.
	var n int
	assert.NoError(t, pool.QueryRow(ctx, `
		SELECT count(*) FROM pg_attribute a
		JOIN pg_class c ON c.oid = a.attrelid
		JOIN pg_namespace ns ON ns.oid = c.relnamespace
		WHERE ns.nspname = current_schema() AND c.relkind = 'r' AND a.attnum > 0
		  AND NOT a.attisdropped AND c.relname <> 'schema_migrations'
		  AND a.atttypid IN ('text'::regtype, 'jsonb'::regtype, 'inet'::regtype, 'cidr'::regtype,
		                     'bytea'::regtype, 'text[]'::regtype)
		  AND coalesce(a.attstattarget, -1) <> 0`).Scan(&n))
	assert.Equal(t, 0, n)
}
