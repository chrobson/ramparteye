package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/chrobson/ramparteye/internal/config"
	"github.com/chrobson/ramparteye/internal/db"
	"github.com/chrobson/ramparteye/internal/model"
	"github.com/chrobson/ramparteye/internal/runner"
	"github.com/chrobson/ramparteye/internal/scan"
	"github.com/chrobson/ramparteye/internal/scope"
	"github.com/chrobson/ramparteye/internal/store"
	"github.com/chrobson/ramparteye/internal/target"
)

// Profiles created from the CLI (seed-demo and scan <targets...>): auto port
// profile (all TCP ports for small targets), at most 1000 packets/s,
// 4 workers, manual only.
const (
	demoProfileName = "Demo"
	profileMaxRate  = 1000
	profileWorkers  = 4
)

func cmdSeedDemo(e *env, args []string) int {
	cfg, code := e.config()
	if code != exitOK {
		return code
	}
	ctx := e.ctx
	sc, err := requireScope(ctx, cfg)
	if err != nil {
		return e.fail("seed-demo", err)
	}
	pool, st, err := openStore(ctx, cfg)
	if err != nil {
		return e.fail("seed-demo", err)
	}
	defer pool.Close()
	if _, err := db.Migrate(ctx, pool); err != nil {
		return e.fail("seed-demo", err)
	}
	res, err := ensureProfile(ctx, st, sc, nil, demoProfileName, seedTargets(cfg, args), []string{"demo"}, defaultProfileRate(cfg))
	if err != nil {
		return e.fail("seed-demo", err)
	}
	out, err := json.Marshal(res)
	if err != nil {
		return e.fail("seed-demo", err)
	}
	fmt.Fprintln(e.stdout, string(out))
	return exitOK
}

// seedTargets returns the targets seed-demo adds when none are given:
// host.docker.internal when the app reaches its host through the docker
// gateway (RAMPART_ALLOW_HOSTS names it), localhost otherwise.
func seedTargets(cfg config.Config, args []string) []string {
	if len(args) > 0 {
		return args
	}
	if slices.Contains(cfg.AllowHosts, "host.docker.internal") {
		return []string{"host.docker.internal"}
	}
	return []string{"localhost"}
}

// defaultProfileRate is the packets/s of a profile created from the CLI,
// never above RAMPART_MAX_RATE.
func defaultProfileRate(cfg config.Config) int {
	if cfg.MaxRate > 0 {
		return min(profileMaxRate, cfg.MaxRate)
	}
	return profileMaxRate
}

// profileStore is the storage ensureProfile needs; *store.Store satisfies it.
type profileStore interface {
	InsertTargets(ctx context.Context, ts []model.Target, createdBy *int64) (int, error)
	Targets(ctx context.Context, tag string) ([]model.Target, error)
	ScanConfigs(ctx context.Context) ([]store.ScanConfig, error)
	CreateScanConfig(ctx context.Context, c store.ScanConfig) (int64, error)
	UpdateScanConfig(ctx context.Context, c store.ScanConfig) error
}

var _ profileStore = (*store.Store)(nil)

type profileResult struct {
	Targets  []string `json:"targets"`
	Imported int      `json:"imported"`
	ConfigID int64    `json:"config_id"`
	Config   string   `json:"config"`
	Created  bool     `json:"created"`
}

// ensureProfile adds the targets (each checked against the scope like any
// import; one refused target refuses them all) and points the profile name
// at exactly these targets. A new profile gets the CLI defaults with the
// given packets/s; an existing one keeps its settings and is enabled.
func ensureProfile(ctx context.Context, st profileStore, sc scope.Scope, resolve target.Resolver,
	name string, values, tags []string, maxRate int) (profileResult, error) {
	res := profileResult{Targets: values, Config: name}
	if len(values) == 0 {
		return res, errors.New("no targets")
	}
	tags, err := target.NormalizeTags(tags)
	if err != nil {
		return res, err
	}
	ts := make([]model.Target, 0, len(values))
	var refused []string
	for _, v := range values {
		t, err := target.Parse(v)
		if err == nil {
			_, err = target.Resolve(ctx, t, resolve, sc)
		}
		if err != nil {
			refused = append(refused, fmt.Sprintf("%s: %v", v, err))
			continue
		}
		t.Tags = tags
		ts = append(ts, t)
	}
	if len(refused) > 0 {
		return res, fmt.Errorf("targets rejected (RAMPART_ALLOWED_CIDRS / RAMPART_ALLOW_HOSTS): %s",
			strings.Join(refused, "; "))
	}
	if res.Imported, err = st.InsertTargets(ctx, ts, nil); err != nil {
		return res, err
	}
	stored, err := st.Targets(ctx, "")
	if err != nil {
		return res, err
	}
	ids := make([]int64, 0, len(ts))
	for _, t := range ts {
		i := slices.IndexFunc(stored, func(s model.Target) bool { return s.Value == t.Value })
		if i < 0 {
			return res, fmt.Errorf("target %q not stored", t.Value)
		}
		ids = append(ids, stored[i].ID)
	}

	cs, err := st.ScanConfigs(ctx)
	if err != nil {
		return res, err
	}
	if i := slices.IndexFunc(cs, func(c store.ScanConfig) bool { return c.Name == name }); i >= 0 {
		c := cs[i]
		c.TargetIDs, c.Enabled = ids, true
		res.ConfigID = c.ID
		return res, st.UpdateScanConfig(ctx, c)
	}
	res.ConfigID, err = st.CreateScanConfig(ctx, store.ScanConfig{Name: name, TargetIDs: ids,
		TopPorts: scan.DefaultTopPorts, MaxRate: maxRate, Workers: profileWorkers, Enabled: true,
		PortProfile: runner.ProfileAuto, ExtraPorts: true})
	res.Created = err == nil
	return res, err
}
