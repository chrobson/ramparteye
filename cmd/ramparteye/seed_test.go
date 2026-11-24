package main

import (
	"context"
	"net/netip"
	"slices"
	"testing"

	"github.com/ctx42/testing/pkg/assert"

	"github.com/chrobson/ramparteye/internal/config"
	"github.com/chrobson/ramparteye/internal/model"
	"github.com/chrobson/ramparteye/internal/scope"
	"github.com/chrobson/ramparteye/internal/store"
)

func mustAddr(s string) netip.Addr { return netip.MustParseAddr(s) }

func mustScope(t *testing.T, cidrs ...string) scope.Scope {
	t.Helper()
	var ps []netip.Prefix
	for _, c := range cidrs {
		ps = append(ps, netip.MustParsePrefix(c))
	}
	s, err := scope.New(ps, nil, nil)
	assert.NoError(t, err)
	return s
}

type fakeProfileStore struct {
	targets []model.Target
	configs []store.ScanConfig
	updated []store.ScanConfig
}

func (f *fakeProfileStore) InsertTargets(_ context.Context, ts []model.Target, _ *int64) (int, error) {
	n := 0
	for _, t := range ts {
		if slices.ContainsFunc(f.targets, func(x model.Target) bool { return x.Value == t.Value }) {
			continue
		}
		t.ID = int64(len(f.targets) + 1)
		f.targets = append(f.targets, t)
		n++
	}
	return n, nil
}

func (f *fakeProfileStore) Targets(context.Context, string) ([]model.Target, error) {
	return f.targets, nil
}

func (f *fakeProfileStore) ScanConfigs(context.Context) ([]store.ScanConfig, error) {
	return f.configs, nil
}

func (f *fakeProfileStore) CreateScanConfig(_ context.Context, c store.ScanConfig) (int64, error) {
	c.ID = int64(len(f.configs) + 100)
	f.configs = append(f.configs, c)
	return c.ID, nil
}

func (f *fakeProfileStore) UpdateScanConfig(_ context.Context, c store.ScanConfig) error {
	f.updated = append(f.updated, c)
	for i := range f.configs {
		if f.configs[i].ID == c.ID {
			f.configs[i] = c
		}
	}
	return nil
}

func TestEnsureProfileCreatesTargetsAndProfile(t *testing.T) {
	st := &fakeProfileStore{targets: []model.Target{{ID: 1, Kind: model.TargetIP, Value: "10.0.0.9"}}}

	res, err := ensureProfile(context.Background(), st, mustScope(t, "10.0.0.0/24"), nil,
		"Demo", []string{"10.0.0.5", "10.0.0.0/30"}, []string{"demo"}, 800)

	assert.NoError(t, err)
	assert.Equal(t, profileResult{Targets: []string{"10.0.0.5", "10.0.0.0/30"}, Imported: 2, ConfigID: 100,
		Config: "Demo", Created: true}, res)
	assert.Len(t, 1, st.configs)
	c := st.configs[0]
	assert.Equal(t, []int64{2, 3}, c.TargetIDs)
	assert.Equal(t, 800, c.MaxRate)
	assert.Equal(t, 4, c.Workers)
	assert.Equal(t, 1000, c.TopPorts)
	assert.Equal(t, "auto", c.PortProfile)
	assert.True(t, c.Enabled)
	assert.True(t, c.ExtraPorts)
	assert.Nil(t, c.EveryMinutes)
	assert.Equal(t, []string{"demo"}, st.targets[1].Tags)
}

func TestEnsureProfileIsIdempotentAndKeepsTuning(t *testing.T) {
	st := &fakeProfileStore{}
	ctx := context.Background()
	s := mustScope(t, "10.0.0.0/24")
	first, err := ensureProfile(ctx, st, s, nil, "CLI", []string{"10.0.0.5"}, nil, 1000)
	assert.NoError(t, err)
	st.configs[0].MaxRate, st.configs[0].Enabled = 50, false

	again, err := ensureProfile(ctx, st, s, nil, "CLI", []string{"10.0.0.6"}, nil, 1000)

	assert.NoError(t, err)
	assert.Equal(t, first.ConfigID, again.ConfigID)
	assert.False(t, again.Created)
	assert.Len(t, 1, st.configs)
	assert.Equal(t, []int64{2}, st.configs[0].TargetIDs)
	assert.Equal(t, 50, st.configs[0].MaxRate)
	assert.True(t, st.configs[0].Enabled)
}

func TestEnsureProfileRefusesOutOfScope(t *testing.T) {
	st := &fakeProfileStore{}

	_, err := ensureProfile(context.Background(), st, mustScope(t, "10.0.0.0/24"), nil,
		"Demo", []string{"10.0.0.5", "8.8.8.8", "10.0.0.0/16"}, nil, 1000)

	assert.ErrorContain(t, "targets rejected (RAMPART_ALLOWED_CIDRS / RAMPART_ALLOW_HOSTS)", err)
	assert.ErrorContain(t, "8.8.8.8", err)
	assert.ErrorContain(t, "10.0.0.0/16", err)
	assert.Len(t, 0, st.targets)
	assert.Len(t, 0, st.configs)
}

func TestEnsureProfileRefusesInvalidAndEmpty(t *testing.T) {
	st := &fakeProfileStore{}
	s := mustScope(t, "10.0.0.0/24")

	_, err := ensureProfile(context.Background(), st, s, nil, "Demo", []string{"not a target!"}, nil, 1000)
	assert.ErrorContain(t, "not a target!", err)

	_, err = ensureProfile(context.Background(), st, s, nil, "Demo", nil, nil, 1000)
	assert.ErrorContain(t, "no targets", err)
}

func TestSeedTargets(t *testing.T) {
	assert.Equal(t, []string{"127.0.0.1"}, seedTargets(config.Config{}, nil))
	assert.Equal(t, []string{"host.docker.internal"},
		seedTargets(config.Config{AllowHosts: []string{"host.docker.internal"}}, nil))
	assert.Equal(t, []string{"127.0.0.1", "::1"},
		seedTargets(config.Config{AllowHosts: []string{"host.docker.internal"}}, []string{"127.0.0.1", "::1"}))
}

func TestDefaultProfileRate(t *testing.T) {
	assert.Equal(t, 1000, defaultProfileRate(config.Config{MaxRate: 5000}))
	assert.Equal(t, 300, defaultProfileRate(config.Config{MaxRate: 300}))
}

func TestSeedWithoutScopeExits2(t *testing.T) {
	e, _, errb := testEnv(nil)

	code := e.run([]string{"ramparteye", "seed-demo"})

	assert.Equal(t, 2, code)
	assert.Contain(t, "no scan scope configured: set RAMPART_ALLOWED_CIDRS", errb.String())
}
