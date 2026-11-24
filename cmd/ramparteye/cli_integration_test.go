//go:build integration

package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/ctx42/testing/pkg/assert"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/chrobson/ramparteye/internal/auth"
	"github.com/chrobson/ramparteye/internal/config"
	"github.com/chrobson/ramparteye/internal/db"
	"github.com/chrobson/ramparteye/internal/model"
	"github.com/chrobson/ramparteye/internal/store"
	"github.com/chrobson/ramparteye/internal/testdb"
)

// schemaDB returns a pool on a fresh empty schema and a database URL that
// points the CLI at the same schema.
func schemaDB(t *testing.T) (*pgxpool.Pool, string) {
	t.Helper()
	pool := testdb.NewEmpty(t)
	var schema string
	assert.NoError(t, pool.QueryRow(context.Background(), `SELECT current_schema()`).Scan(&schema))
	u, err := url.Parse(os.Getenv(testdb.EnvURL))
	assert.NoError(t, err)
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	return pool, u.String()
}

func migrated(t *testing.T) (*pgxpool.Pool, string) {
	t.Helper()
	pool, dbURL := schemaDB(t)
	_, err := db.Migrate(context.Background(), pool)
	assert.NoError(t, err)
	return pool, dbURL
}

func TestMigrateIntegration(t *testing.T) {
	pool, dbURL := schemaDB(t)
	vars := map[string]string{"RAMPART_DATABASE_URL": dbURL}

	e, out, errb := testEnv(vars)
	code := e.run([]string{"ramparteye", "migrate"})

	assert.Equal(t, 0, code, errb.String())
	assert.Contain(t, "applied migrations: 0001_schema, 0002_roles", out.String())
	var n int
	assert.NoError(t, pool.QueryRow(context.Background(), `SELECT count(*) FROM users`).Scan(&n))

	e, out, _ = testEnv(vars)
	assert.Equal(t, 0, e.run([]string{"ramparteye", "migrate"}))
	assert.Equal(t, "database schema is up to date\n", out.String())
}

func TestMigrateUnreachableDatabaseExits1(t *testing.T) {
	e, _, errb := testEnv(map[string]string{
		"RAMPART_DATABASE_URL": "postgres://nobody:nothing@127.0.0.1:1/none?sslmode=disable&connect_timeout=2"})

	code := e.run([]string{"ramparteye", "migrate"})

	assert.Equal(t, 1, code)
	assert.Contain(t, "ramparteye: migrate: ping database", errb.String())
}

var passwordLine = regexp.MustCompile(`new password for admin \(shown once, must be changed at login\): (\S+)\n`)

func TestResetAdminIntegration(t *testing.T) {
	ctx := context.Background()
	pool, dbURL := migrated(t)
	st := store.New(pool)
	hash, err := auth.HashPassword("old-password")
	assert.NoError(t, err)
	id, err := st.CreateUser(ctx, model.NewUser{Login: "admin", PasswordHash: hash, Role: auth.RoleAdmin})
	assert.NoError(t, err)
	_, err = st.CreateUser(ctx, model.NewUser{Login: "second", PasswordHash: hash, Role: auth.RoleAdmin})
	assert.NoError(t, err)
	assert.NoError(t, st.SetUserDisabled(ctx, id, true))
	token := []byte("session-token-hash")
	assert.NoError(t, st.CreateSession(ctx, token, id, time.Now().Add(time.Hour)))
	e, out, errb := testEnv(map[string]string{"RAMPART_DATABASE_URL": dbURL})

	code := e.run([]string{"ramparteye", "reset-admin"})

	assert.Equal(t, 0, code, errb.String())
	m := passwordLine.FindStringSubmatch(out.String())
	assert.Len(t, 2, m)
	assert.Equal(t, 1, strings.Count(out.String(), m[1]))
	u, err := st.UserByID(ctx, id)
	assert.NoError(t, err)
	assert.True(t, auth.CheckPassword(u.PasswordHash, m[1]))
	assert.False(t, auth.CheckPassword(u.PasswordHash, "old-password"))
	assert.True(t, u.MustChangePassword)
	assert.False(t, u.Disabled)
	_, err = st.SessionUser(ctx, token)
	assert.Error(t, err)
	entries, err := st.AuditEntries(ctx, 10)
	assert.NoError(t, err)
	assert.Equal(t, auditPasswordReset, entries[0].Action)
	assert.Equal(t, "user:admin", entries[0].Entity)
	assert.Nil(t, entries[0].UserID)
	assert.Contain(t, `"actor": "cli"`, entries[0].Details)
}

func TestResetAdminUnknownLoginIntegration(t *testing.T) {
	_, dbURL := migrated(t)
	e, out, errb := testEnv(map[string]string{"RAMPART_DATABASE_URL": dbURL})

	code := e.run([]string{"ramparteye", "reset-admin", "--login", "ghost"})

	assert.Equal(t, 1, code)
	assert.Equal(t, "", out.String())
	assert.Contain(t, `ramparteye: reset-admin: no user with login "ghost"`, errb.String())
}

func TestServeSmokeIntegration(t *testing.T) {
	_, dbURL := schemaDB(t)
	secrets := filepath.Join(t.TempDir(), "secrets")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	e, out, errb := testEnv(map[string]string{
		"RAMPART_DATABASE_URL":  dbURL,
		"RAMPART_HTTP_ADDR":     "127.0.0.1:0",
		"RAMPART_SECRETS_DIR":   secrets,
		"RAMPART_ALLOWED_CIDRS": "127.0.0.1/32",
	})
	e.ctx = ctx
	addr := make(chan string, 1)
	e.onListen = func(a string) { addr <- a }
	done := make(chan int, 1)

	go func() { done <- e.run([]string{"ramparteye", "serve"}) }()

	var base string
	select {
	case a := <-addr:
		base = "http://" + a
	case code := <-done:
		t.Fatalf("serve exited with %d: %s", code, errb.String())
	case <-time.After(30 * time.Second):
		t.Fatal("serve did not start listening")
	}
	res, err := http.Get(base + "/login")
	assert.NoError(t, err)
	_ = res.Body.Close()
	assert.Equal(t, http.StatusOK, res.StatusCode)
	assert.Equal(t, "DENY", res.Header.Get("X-Frame-Options"))
	assert.Equal(t, "nosniff", res.Header.Get("X-Content-Type-Options"))
	assert.NotEmpty(t, res.Header.Get("Content-Security-Policy"))
	assert.NotEmpty(t, res.Header.Get("X-Rampart-Instance"))
	assert.Equal(t, 1, strings.Count(out.String(), "shown once"))
	fi, err := os.Stat(filepath.Join(secrets, keyFileName))
	assert.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), fi.Mode().Perm())

	cancel()

	select {
	case code := <-done:
		assert.Equal(t, 0, code, errb.String())
	case <-time.After(30 * time.Second):
		t.Fatal("serve did not shut down")
	}
	assert.Contain(t, `"msg":"shutting down"`, errb.String())
}

func TestServeRestartReusesKeyAndAccountsIntegration(t *testing.T) {
	_, dbURL := schemaDB(t)
	secrets := filepath.Join(t.TempDir(), "secrets")
	start := func() string {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		e, out, errb := testEnv(map[string]string{"RAMPART_DATABASE_URL": dbURL,
			"RAMPART_HTTP_ADDR": "127.0.0.1:0", "RAMPART_SECRETS_DIR": secrets})
		e.ctx = ctx
		e.onListen = func(string) { cancel() }
		assert.Equal(t, 0, e.run([]string{"ramparteye", "serve"}), errb.String())
		return out.String()
	}
	first := start()
	key1, err := os.ReadFile(filepath.Join(secrets, keyFileName))
	assert.NoError(t, err)

	second := start()

	key2, err := os.ReadFile(filepath.Join(secrets, keyFileName))
	assert.NoError(t, err)
	assert.Equal(t, key1, key2)
	assert.Contain(t, "shown once", first)
	assert.Equal(t, "", second)
}

func TestSeedDemoIntegration(t *testing.T) {
	ctx := context.Background()
	pool, dbURL := schemaDB(t)
	vars := map[string]string{"RAMPART_DATABASE_URL": dbURL, "RAMPART_ALLOWED_CIDRS": "127.0.0.0/8"}
	seed := func(args ...string) (int, profileResult, string) {
		e, out, errb := testEnv(vars)
		code := e.run(append([]string{"ramparteye", "seed-demo"}, args...))
		var res profileResult
		if code == 0 {
			assert.NoError(t, json.Unmarshal(out.Bytes(), &res))
		}
		return code, res, errb.String()
	}

	code, res, errs := seed("127.0.0.1")
	assert.Equal(t, 0, code, errs)
	assert.True(t, res.Created)
	assert.Equal(t, 1, res.Imported)

	code, again, _ := seed("127.0.0.1")
	assert.Equal(t, 0, code)
	assert.Equal(t, res.ConfigID, again.ConfigID)
	assert.Equal(t, 0, again.Imported)
	c, err := store.New(pool).ScanConfig(ctx, res.ConfigID)
	assert.NoError(t, err)
	assert.Equal(t, "Demo", c.Name)
	assert.Equal(t, "auto", c.PortProfile)
	assert.Equal(t, 1000, c.MaxRate)
	assert.Len(t, 1, c.TargetIDs)

	code, _, errs = seed("8.8.8.8")
	assert.Equal(t, 1, code)
	assert.Contain(t, "targets rejected", errs)
}

func TestLoadObservedIntegration(t *testing.T) {
	ctx := context.Background()
	pool, _ := migrated(t)
	exec := func(sql string, args ...any) {
		t.Helper()
		_, err := pool.Exec(ctx, sql, args...)
		assert.NoError(t, err)
	}
	exec(`INSERT INTO scan_runs (id, status, duration_ms) VALUES (1, 'done', 10), (2, 'done', 1500)`)
	exec(`INSERT INTO host_obs (run_id, ip, up) VALUES (2, '10.20.0.10', true), (2, '10.20.0.11', false)`)
	exec(`INSERT INTO services (id, run_id, ip, port, proto) VALUES (7, 2, '10.20.0.10', 80, 'tcp')`)
	exec(`INSERT INTO detections (service_id, signature_id, name, category, confidence)
		VALUES (7, 'staging-env', 'Staging', 'staging', 90)`)
	exec(`INSERT INTO changes (run_id, prev_run_id, kind, ip, port, proto) VALUES (2, 1, 'new', '10.20.0.10', 80, 'tcp')`)
	exec(`INSERT INTO diff_runs (run_id, prev_run_id) VALUES (2, 1)`)

	obs, err := loadObserved(ctx, pool, 2)

	assert.NoError(t, err)
	assert.Equal(t, int64(1), obs.PrevRunID)
	assert.Equal(t, int64(1500), *obs.DurationMS)
	assert.Equal(t, []string{"10.20.0.10"}, obs.Hosts)
	assert.Equal(t, []obsService{{"10.20.0.10", 80, "tcp"}}, obs.Services)
	assert.Equal(t, []obsDetection{{"10.20.0.10", 80, "staging-env"}}, obs.Detections)
	assert.Equal(t, []obsChange{{"new", "10.20.0.10", 80, "tcp"}}, obs.Changes)

	_, err = loadObserved(ctx, pool, 99)
	assert.ErrorContain(t, "run 99", err)
}

func TestScannerReloadsSignaturesIntegration(t *testing.T) {
	ctx := context.Background()
	pool, _ := migrated(t)
	st := store.New(pool)
	box, _, err := loadBox(&config.Config{SecretsDir: t.TempDir()})
	assert.NoError(t, err)
	s := newScanner(config.Config{}, st, mustScope(t, "127.0.0.1/32"), box, slog.New(slog.DiscardHandler))
	assert.NoError(t, s.runner.Recover(ctx))
	n := len(s.engine.Signatures())
	assert.True(t, n > 0)

	assert.NoError(t, st.SetSignatureEnabled(ctx, "nginx", false))
	s.reloadSignatures(ctx)

	assert.Len(t, n-1, s.engine.Signatures())
}

func TestDBCommandsIntegration(t *testing.T) {
	_, dbURL := migrated(t)
	vars := map[string]string{"RAMPART_DATABASE_URL": dbURL, "RAMPART_SECRETS_DIR": t.TempDir(),
		"RAMPART_ALLOWED_CIDRS": "127.0.0.1/32"}
	for name, tc := range map[string]struct {
		args []string
		want string
	}{
		"dojo push":      {[]string{"dojo", "push"}, "ramparteye: dojo: DefectDojo is not configured"},
		"audit":          {[]string{"audit"}, "ramparteye: audit: no safety receipt for this run"},
		"export":         {[]string{"export"}, "ramparteye: export: no finished run to export"},
		"export run":     {[]string{"export", "--run", "5"}, "ramparteye: export: run 5 not found or not finished"},
		"verify":         {[]string{"verify", writeFile(t, "run1.json", labExpected)}, "ramparteye: verify: no finished run to verify"},
		"scan profile":   {[]string{"scan", "--profile", "Nope"}, `ramparteye: scan: no scan profile named "Nope"`},
		"scan out scope": {[]string{"scan", "10.0.0.1"}, "targets rejected"},
		"import":         {[]string{"import", writeFile(t, "x.txt", "hello")}, "ramparteye: import: unknown import format"},
	} {
		t.Run(name, func(t *testing.T) {
			e, out, errb := testEnv(vars)

			code := e.run(append([]string{"ramparteye"}, tc.args...))

			assert.Equal(t, 1, code)
			assert.Contain(t, tc.want, errb.String())
			if name != "import" {
				assert.Equal(t, "", out.String())
			}
		})
	}
}
