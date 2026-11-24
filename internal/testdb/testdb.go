// Package testdb gives integration tests an isolated, migrated database
// schema on the server named by RAMPART_TEST_DATABASE_URL.
package testdb

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/chrobson/ramparteye/internal/db"
)

// EnvURL names the variable holding the test server URL.
const EnvURL = "RAMPART_TEST_DATABASE_URL"

// New returns a pool bound to a fresh schema with every migration applied.
// The schema is dropped when the test ends. The test is skipped when
// RAMPART_TEST_DATABASE_URL is unset.
func New(t testing.TB) *pgxpool.Pool {
	t.Helper()
	pool := NewEmpty(t)
	if _, err := db.Migrate(context.Background(), pool); err != nil {
		t.Fatalf("testdb: migrate: %v", err)
	}
	return pool
}

// NewEmpty is New without migrations.
func NewEmpty(t testing.TB) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv(EnvURL)
	if url == "" {
		t.Skip(EnvURL + " not set")
	}
	ctx := context.Background()
	admin, err := db.Open(ctx, url)
	if err != nil {
		t.Fatalf("testdb: open: %v", err)
	}
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	schema := "test_" + hex.EncodeToString(b)
	ident := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+ident); err != nil {
		admin.Close()
		t.Fatalf("testdb: create schema: %v", err)
	}

	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatalf("testdb: parse url: %v", err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("testdb: pool: %v", err)
	}
	t.Cleanup(func() {
		pool.Close()
		_, _ = admin.Exec(context.Background(), "DROP SCHEMA "+ident+" CASCADE")
		admin.Close()
	})
	return pool
}
