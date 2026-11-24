//go:build integration

package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ctx42/testing/pkg/assert"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/chrobson/ramparteye/internal/auth"
	"github.com/chrobson/ramparteye/internal/config"
	"github.com/chrobson/ramparteye/internal/db"
	"github.com/chrobson/ramparteye/internal/dojo"
	"github.com/chrobson/ramparteye/internal/model"
	"github.com/chrobson/ramparteye/internal/scan"
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
	assert.Contain(t, `"reenabled": true`, entries[0].Details)
	assert.Contain(t, "Login lockout (if any) clears within 15 minutes or on restart of serve.\n", out.String())
}

func TestCommandsNeedExistingKeyIntegration(t *testing.T) {
	_, dbURL := migrated(t)
	secrets := t.TempDir()
	vars := map[string]string{"RAMPART_DATABASE_URL": dbURL, "RAMPART_SECRETS_DIR": secrets,
		"RAMPART_ALLOWED_CIDRS": "127.0.0.1/32"}
	for _, args := range [][]string{{"dojo", "push"}, {"scan", "127.0.0.1"}} {
		e, _, errb := testEnv(vars)

		code := e.run(append([]string{"ramparteye"}, args...))

		assert.Equal(t, 1, code)
		assert.Contain(t, "secret key not found in "+secrets, errb.String())
	}
	_, err := os.Stat(filepath.Join(secrets, keyFileName))
	assert.ErrorIs(t, os.ErrNotExist, err)
}

func TestScanMigratesIntegration(t *testing.T) {
	_, dbURL := schemaDB(t)
	secrets := t.TempDir()
	_, _, err := loadBox(&config.Config{SecretsDir: secrets}, true)
	assert.NoError(t, err)
	e, _, errb := testEnv(map[string]string{"RAMPART_DATABASE_URL": dbURL, "RAMPART_SECRETS_DIR": secrets,
		"RAMPART_ALLOWED_CIDRS": "127.0.0.1/32"})

	code := e.run([]string{"ramparteye", "scan", "--profile", "Nope"})

	assert.Equal(t, 1, code)
	assert.Contain(t, `no scan profile named "Nope"`, errb.String())
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

// The web UI's SignaturesChanged hook reloads the runner's engine.
func TestSignaturesChangedReloadsRunnerIntegration(t *testing.T) {
	ctx := context.Background()
	pool, _ := migrated(t)
	st := store.New(pool)
	cfg := config.Config{SecretsDir: t.TempDir()}
	box, _, err := loadBox(&cfg, true)
	assert.NoError(t, err)
	log := slog.New(slog.DiscardHandler)
	sc := mustScope(t, "127.0.0.1/32")
	s := newScanner(cfg, st, sc, box, log, nil)
	assert.NoError(t, s.runner.Recover(ctx))
	n := len(s.runner.Signatures())
	assert.True(t, n > 0)
	deps := serveDeps(ctx, pool, st, s, sc, cfg, box, log)

	assert.NoError(t, st.SetSignatureEnabled(ctx, "nginx", false))
	deps.SignaturesChanged()

	assert.Len(t, n-1, s.runner.Signatures())
	for _, sg := range s.runner.Signatures() {
		assert.NotEqual(t, "nginx", sg.ID)
	}
	assert.NoError(t, st.SetSignatureEnabled(ctx, "nginx", true))
	deps.SignaturesChanged()
	assert.Len(t, n, s.runner.Signatures())
}

// fakeNmap reports 127.0.0.1 up with ssh on port 22.
type fakeNmap struct{}

func (fakeNmap) Discover(_ context.Context, ps []netip.Prefix, _ scan.Opts) (scan.Result, error) {
	now := time.Now()
	return scan.Result{Hosts: []model.HostObs{{IP: netip.MustParseAddr("127.0.0.1"), Up: true}},
		Runs: []scan.Run{{Argv: []string{"-sn", "-n"}, Targets: ps, Packets: 2, Elapsed: time.Millisecond,
			Start: now.Add(-time.Millisecond), End: now}}}, nil
}

func (fakeNmap) Services(_ context.Context, hosts []netip.Addr, _ scan.Opts) (scan.Result, error) {
	now := time.Now()
	res := scan.Result{Runs: []scan.Run{{Argv: []string{"-sV", "-n"}, Packets: 2, Elapsed: time.Millisecond,
		Start: now.Add(-time.Millisecond), End: now}}}
	for _, h := range hosts {
		res.Runs[0].Targets = append(res.Runs[0].Targets, netip.PrefixFrom(h, 32))
		res.Services = append(res.Services, model.ServiceObs{Key: model.AssetKey{IP: h, Port: 22, Proto: "tcp"},
			Banner: "ssh", Product: "OpenSSH"})
	}
	return res, nil
}

// A run that finishes is pushed to DefectDojo through runner.OnRunDone and
// recorded in the push history.
func TestFinishedRunReachesPusherIntegration(t *testing.T) {
	ctx := context.Background()
	pool, _ := migrated(t)
	st := store.New(pool)
	var mu sync.Mutex
	var titles []string
	dd := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v2/reimport-scan/" || r.Header.Get("Authorization") != "Token tok" {
			http.Error(w, "unexpected", http.StatusBadRequest)
			return
		}
		mu.Lock()
		titles = append(titles, r.FormValue("test_title"))
		mu.Unlock()
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"test": 3, "statistics": {}}`))
	}))
	defer dd.Close()
	cfg, err := config.Load(func(k string) string {
		return map[string]string{"RAMPART_SECRETS_DIR": t.TempDir(), "RAMPART_DOJO_URL": dd.URL,
			"RAMPART_DOJO_TOKEN": "tok", "RAMPART_DOJO_PRODUCT": "Perimeter"}[k]
	})
	assert.NoError(t, err)
	box, _, err := loadBox(&cfg, true)
	assert.NoError(t, err)
	log := slog.New(slog.DiscardHandler)
	sc := mustScope(t, "127.0.0.1/32")
	res, err := ensureProfile(ctx, st, sc, nil, "Push", []string{"127.0.0.1"}, nil, 100)
	assert.NoError(t, err)
	s := newScanner(cfg, st, sc, box, log, fakeNmap{})
	assert.NoError(t, s.runner.Recover(ctx))

	runID, err := s.runner.Start(ctx, res.ConfigID)
	assert.NoError(t, err)
	s.runner.Wait()
	assert.Wait(t, 10*time.Second, func() bool {
		ps, err := st.DojoPushes(ctx, 10)
		return err == nil && len(ps) == 1
	})
	shutdown(log, 5*time.Second, shutdownSteps{waitRuns: s.runner.Wait, closePusher: s.pusher.Close})

	run, err := st.Run(ctx, runID)
	assert.NoError(t, err)
	assert.Equal(t, store.RunDone, run.Status)
	pushes, err := st.DojoPushes(ctx, 10)
	assert.NoError(t, err)
	assert.Equal(t, runID, *pushes[0].RunID)
	assert.Equal(t, "auto", pushes[0].Trigger)
	assert.True(t, pushes[0].OK, pushes[0].Error)
	assert.Equal(t, []string{dojo.TestTitle("Push")}, titles)
}

func TestDBCommandsIntegration(t *testing.T) {
	_, dbURL := migrated(t)
	secrets := t.TempDir()
	_, _, err := loadBox(&config.Config{SecretsDir: secrets}, true)
	assert.NoError(t, err)
	vars := map[string]string{"RAMPART_DATABASE_URL": dbURL, "RAMPART_SECRETS_DIR": secrets,
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
