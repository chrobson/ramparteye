package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/chrobson/ramparteye/internal/config"
	"github.com/chrobson/ramparteye/internal/db"
	"github.com/chrobson/ramparteye/internal/diff"
	"github.com/chrobson/ramparteye/internal/dojo"
	"github.com/chrobson/ramparteye/internal/httpfp"
	"github.com/chrobson/ramparteye/internal/runner"
	"github.com/chrobson/ramparteye/internal/scan"
	"github.com/chrobson/ramparteye/internal/scope"
	"github.com/chrobson/ramparteye/internal/secret"
	"github.com/chrobson/ramparteye/internal/sig"
	"github.com/chrobson/ramparteye/internal/store"
	"github.com/chrobson/ramparteye/internal/target"
	"github.com/chrobson/ramparteye/internal/web"
)

// keyFileName is the AES key file in RAMPART_SECRETS_DIR.
const keyFileName = "secret.key"

// errNoScope is the CLI form of scope.ErrNoScope.
var errNoScope = errors.New("no scan scope configured: set RAMPART_ALLOWED_CIDRS (and optionally RAMPART_ALLOW_HOSTS)")

// usageError is an argument error; it exits with exitUsage.
type usageError string

func (u usageError) Error() string { return string(u) }

// fail prints err and returns its exit code: exitUsage for argument and
// scope errors, exitFail otherwise.
func (e *env) fail(cmd string, err error) int {
	var u usageError
	switch {
	case errors.As(err, &u):
		fmt.Fprintln(e.stderr, u)
		return exitUsage
	case errors.Is(err, errNoScope), errors.Is(err, scope.ErrNoScope):
		fmt.Fprintln(e.stderr, "ramparteye:", errNoScope)
		return exitUsage
	}
	fmt.Fprintf(e.stderr, "ramparteye: %s: %v\n", cmd, err)
	return exitFail
}

// config loads the configuration; a bad value is reported with exitUsage.
func (e *env) config() (config.Config, int) {
	cfg, err := config.Load(e.getenv)
	if err != nil {
		fmt.Fprintf(e.stderr, "ramparteye: configuration: %v\n", err)
		return cfg, exitUsage
	}
	return cfg, exitOK
}

// logger writes JSON logs to stderr. Config values are only ever logged
// through Config.String, which redacts secrets.
func (e *env) logger() *slog.Logger { return slog.New(slog.NewJSONHandler(e.stderr, nil)) }

// flags returns a flag set that reports errors through the returned error
// only (fail prints them with the usage line).
func flags(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	return fs
}

// parseFlags parses args and turns a flag error into a usage error.
func parseFlags(fs *flag.FlagSet, args []string, usage string) error {
	if err := fs.Parse(args); err != nil {
		return usageError(fmt.Sprintf("%v\n%s", err, usage))
	}
	return nil
}

// parseRunID parses a positive run id.
func parseRunID(s string) (int64, error) {
	id, err := strconv.ParseInt(s, 10, 64)
	if err != nil || id < 1 {
		return 0, usageError(fmt.Sprintf("invalid run id %q", s))
	}
	return id, nil
}

// runIDFlag is a --run flag holding a positive run id (0 = not given).
type runIDFlag int64

func (r *runIDFlag) String() string { return strconv.FormatInt(int64(*r), 10) }

func (r *runIDFlag) Set(s string) error {
	id, err := parseRunID(s)
	if err != nil {
		return err
	}
	*r = runIDFlag(id)
	return nil
}

// openStore opens the database named by cfg.
func openStore(ctx context.Context, cfg config.Config) (*pgxpool.Pool, *store.Store, error) {
	pool, err := db.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return nil, nil, err
	}
	return pool, store.New(pool), nil
}

// exchange opens the result store for import and export.
func (e *env) exchange(ctx context.Context, cfg config.Config) (web.Exchange, func(), error) {
	if e.openExchange != nil {
		return e.openExchange(ctx, cfg)
	}
	pool, _, err := openStore(ctx, cfg)
	if err != nil {
		return nil, nil, err
	}
	return web.NewExchange(pool), pool.Close, nil
}

// buildScope builds the scan scope from RAMPART_ALLOWED_CIDRS, the resolved
// RAMPART_ALLOW_HOSTS and RAMPART_SCAN_EXCLUDE. Nothing configured gives
// the empty scope, which refuses every scan and import.
func buildScope(ctx context.Context, cfg config.Config, resolve config.Resolver) (scope.Scope, error) {
	if len(cfg.AllowedCIDRs) == 0 && len(cfg.AllowHosts) == 0 {
		return scope.Scope{}, nil
	}
	hostPrefixes, err := config.ResolveAllowHosts(ctx, cfg.AllowHosts, resolve)
	if err != nil {
		return scope.Scope{}, fmt.Errorf("RAMPART_ALLOW_HOSTS: %w", err)
	}
	hosts := make([]netip.Addr, len(hostPrefixes))
	for i, p := range hostPrefixes {
		hosts[i] = p.Addr()
	}
	return scope.New(cfg.AllowedCIDRs, hosts, cfg.ScanExclude)
}

// requireScope builds the scope and refuses an empty one with errNoScope.
func requireScope(ctx context.Context, cfg config.Config) (scope.Scope, error) {
	if len(cfg.AllowedCIDRs) == 0 && len(cfg.AllowHosts) == 0 {
		return scope.Scope{}, errNoScope
	}
	sc, err := buildScope(ctx, cfg, config.DefaultResolver)
	if err != nil {
		return sc, err
	}
	if sc.Empty() {
		return sc, errNoScope
	}
	return sc, nil
}

// loadBox loads (or creates on first start) the AES key and stores it in
// cfg.SecretKey, which also keys the instance id shared by every process.
func loadBox(cfg *config.Config) (*secret.Box, bool, error) {
	key, created, err := secret.LoadOrCreate(cfg.SecretsDir, keyFileName, secret.KeySize, cfg.SecretKey)
	if err != nil {
		return nil, false, fmt.Errorf("secret key: %w", err)
	}
	cfg.SecretKey = key
	box, err := secret.NewBox(key)
	if err != nil {
		return nil, false, fmt.Errorf("secret key: %w", err)
	}
	return box, created, nil
}

// scanner is the scan machinery shared by `serve` and `scan`: one runner
// with its signature engine, and the DefectDojo pusher on its run hook.
type scanner struct {
	runner *runner.Runner
	engine *sig.Engine
	pusher *dojo.Pusher
	st     *store.Store
	log    *slog.Logger
}

func newScanner(cfg config.Config, st *store.Store, sc scope.Scope, box *secret.Box, log *slog.Logger) *scanner {
	retries := cfg.HTTPRetries
	if retries == 0 {
		retries = -1 // httpfp: 0 selects the default, negative disables retries
	}
	prober := httpfp.New(httpfp.Options{
		Timeout:  cfg.HTTPTimeout,
		Retries:  retries,
		Scope:    sc,
		Resolver: httpfp.Resolver(config.DefaultResolver),
		// A warm second sample keeps cold starts out of the latency diff.
		LatencySample: true,
		UserAgent:     "ramparteye/" + version + " (+attack surface inventory)",
	})
	eng := sig.NewEngine(nil, sig.NewHTTPFetcher(prober))
	r := runner.New(st, scan.NewNmap(cfg.NmapPath, sc, nil), prober, eng, sc, runner.Config{
		Privileged:       cfg.ScanPrivileged,
		MaxRate:          cfg.MaxRate,
		AllowedPorts:     cfg.ScanPorts,
		AllPortsMaxAddrs: cfg.AllPortsMaxAddrs,
		Resolver:         target.Resolver(config.DefaultResolver),
		Unstable:         diff.Config(cfg.Unstable),
		HTTPTimeout:      cfg.HTTPTimeout,
		Log:              log,
	})
	p := dojo.NewPusher(st, dojo.StoredSettings(st, box, cfg), dojo.DefaultClient)
	p.Log = log
	r.OnRunDone = p.OnRunDone
	return &scanner{runner: r, engine: eng, pusher: p, st: st, log: log}
}

// reloadSignatures loads the enabled signatures into the engine; the runner
// uses the new set for runs that start afterwards. A partly broken set is
// still loaded (the broken ones are logged).
func (s *scanner) reloadSignatures(ctx context.Context) {
	sigs, err := sig.LoadEnabled(ctx, s.st)
	if err != nil {
		s.log.Warn("some signatures not loaded", "err", err)
	}
	if sigs != nil || err == nil {
		s.engine.SetSignatures(sigs)
	}
}

// stop waits for the runner's runs to stop (their context must be done
// already), then closes the pusher: no OnRunDone call can follow.
func (s *scanner) stop(timeout time.Duration) {
	s.runner.Wait()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if err := s.pusher.Close(ctx); err != nil {
		s.log.Warn("DefectDojo pushes still running at exit", "err", err)
	}
}
