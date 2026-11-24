package dojo

import (
	"bytes"
	"context"
	"testing"

	"github.com/ctx42/testing/pkg/assert"
	"github.com/ctx42/testing/pkg/must"

	"github.com/chrobson/ramparteye/internal/config"
	"github.com/chrobson/ramparteye/internal/secret"
	"github.com/chrobson/ramparteye/internal/store"
)

// memStore is an in-memory SettingsStore holding the single row.
type memStore struct {
	row   store.DojoConfig
	err   error // returned by DojoConfig when set
	saves int
}

func (m *memStore) DojoConfig(context.Context) (store.DojoConfig, error) {
	if m.err != nil {
		return store.DojoConfig{}, m.err
	}
	return m.row, nil
}

func (m *memStore) SaveDojoConfig(_ context.Context, c store.DojoConfig) error {
	m.saves++
	if c.TokenEnc == nil {
		c.TokenEnc = m.row.TokenEnc
	}
	m.row = c
	return nil
}

func testBox(t *testing.T) *secret.Box {
	t.Helper()
	return must.Value(secret.NewBox(bytes.Repeat([]byte{9}, 32)))
}

func envCfg() config.Config {
	return config.Config{
		DojoURL: "https://env.example", DojoToken: "env-token", DojoProductType: "EnvPT",
		DojoProduct: "EnvProduct", DojoEngagement: "EnvEng", DojoAutoPush: false, DojoCloseMissing: true,
	}
}

func TestLoadDefaultsWhenRowEmpty(t *testing.T) {
	st := &memStore{err: store.ErrNotFound}

	have, err := LoadSettings(context.Background(), st, testBox(t), config.Config{})

	assert.NoError(t, err)
	assert.Equal(t, Settings{
		ProductType: "RampartEye", Engagement: "Continuous discovery", AutoPush: true,
	}, have)
}

func TestEnvOverridesDB(t *testing.T) {
	st := &memStore{row: store.DojoConfig{URL: "https://db.example", ProductType: "DB", AutoPush: true}}

	have, err := LoadSettings(context.Background(), st, testBox(t), envCfg())

	assert.NoError(t, err)
	assert.Equal(t, Settings{
		URL: "https://env.example", ProductType: "EnvPT", Product: "EnvProduct", Engagement: "EnvEng",
		AutoPush: false, CloseMissing: true, ManagedByEnv: true, TokenSet: true,
	}, have)
}

func TestPartialEnvWithoutURLIgnored(t *testing.T) {
	st := &memStore{row: store.DojoConfig{URL: "https://db.example", ProductType: "DB", Engagement: "E"}}

	have, err := LoadSettings(context.Background(), st, testBox(t), config.Config{DojoToken: "x", DojoProduct: "P"})

	assert.NoError(t, err)
	assert.Equal(t, "https://db.example", have.URL)
	assert.False(t, have.ManagedByEnv)
	assert.False(t, have.TokenSet)
}

func TestLoadRejectsInvalidEnvURL(t *testing.T) {
	cfg := envCfg()
	cfg.DojoURL = "dojo.example"

	_, err := LoadSettings(context.Background(), &memStore{}, testBox(t), cfg)

	assert.ErrorContain(t, "DefectDojo URL", err)
}

func TestSaveRefusedWhenManaged(t *testing.T) {
	st := &memStore{}

	err := SaveSettings(context.Background(), st, testBox(t), envCfg(), Settings{URL: "https://x.example"})

	assert.ErrorIs(t, ErrManagedByEnv, err)
	assert.Equal(t, 0, st.saves)

	err = SaveSettings(context.Background(), st, testBox(t), config.Config{},
		Settings{URL: "https://x.example", ManagedByEnv: true})
	assert.ErrorIs(t, ErrManagedByEnv, err)
	assert.Equal(t, 0, st.saves)
}

func TestEmptyTokenKeepsExisting(t *testing.T) {
	ctx, st, box := context.Background(), &memStore{}, testBox(t)
	assert.NoError(t, SaveSettings(ctx, st, box, config.Config{}, Settings{URL: "https://d.example", Token: "first"}))

	assert.NoError(t, SaveSettings(ctx, st, box, config.Config{}, Settings{URL: "https://d2.example"}))
	tok, err := loadToken(ctx, st, box, config.Config{})
	assert.NoError(t, err)
	assert.Equal(t, "first", tok)
	assert.Equal(t, "https://d2.example", st.row.URL)

	assert.NoError(t, SaveSettings(ctx, st, box, config.Config{}, Settings{URL: "https://d2.example", Token: "second"}))
	tok, err = loadToken(ctx, st, box, config.Config{})
	assert.NoError(t, err)
	assert.Equal(t, "second", tok)
}

func TestTokenEncryptedAtRest(t *testing.T) {
	ctx, st, box := context.Background(), &memStore{}, testBox(t)

	assert.NoError(t, SaveSettings(ctx, st, box, config.Config{}, Settings{URL: "https://d.example", Token: "s3cret-token"}))

	assert.False(t, bytes.Contains(st.row.TokenEnc, []byte("s3cret-token")))
	plain, err := box.Open(st.row.TokenEnc, "dojo_config:token")
	assert.NoError(t, err)
	assert.Equal(t, "s3cret-token", string(plain))
	_, err = box.Open(st.row.TokenEnc, "other")
	assert.Error(t, err)
}

func TestLoadSettingsNeverReturnsToken(t *testing.T) {
	ctx, st, box := context.Background(), &memStore{}, testBox(t)
	assert.NoError(t, SaveSettings(ctx, st, box, config.Config{}, Settings{URL: "https://d.example", Token: "tok"}))

	have, err := LoadSettings(ctx, st, box, config.Config{})

	assert.NoError(t, err)
	assert.Equal(t, "", have.Token)
	assert.True(t, have.TokenSet)
}

func TestLoadTokenFromEnvAndMissing(t *testing.T) {
	ctx, box := context.Background(), testBox(t)

	tok, err := loadToken(ctx, &memStore{}, box, envCfg())
	assert.NoError(t, err)
	assert.Equal(t, "env-token", tok)

	_, err = loadToken(ctx, &memStore{}, box, config.Config{})
	assert.ErrorIs(t, ErrNoToken, err)
}

func TestLoadSettingsCorruptTokenIsNotFatal(t *testing.T) {
	// Settings must still render so the operator can replace a token sealed
	// with a lost key; only loadToken fails.
	ctx, box := context.Background(), testBox(t)
	st := &memStore{row: store.DojoConfig{URL: "https://d.example", TokenEnc: []byte("garbage-garbage-garbage-garbage")}}

	have, err := LoadSettings(ctx, st, box, config.Config{})
	assert.NoError(t, err)
	assert.True(t, have.TokenSet)

	_, err = loadToken(ctx, st, box, config.Config{})
	assert.Error(t, err)
}

func TestRejectRelativeURL(t *testing.T) {
	ctx, box := context.Background(), testBox(t)
	for _, u := range []string{
		"dojo.example", "/dojo", "ftp://dojo.example", "https://", "//dojo.example",
		"https://user:pw@dojo.example", "https://dojo.example/?a=1", "https://dojo.example/#f", "https://dojo.example?",
	} {
		st := &memStore{}
		err := SaveSettings(ctx, st, box, config.Config{}, Settings{URL: u, Token: "t"})
		assert.ErrorContain(t, "DefectDojo URL", err, u)
		assert.Equal(t, 0, st.saves, u)
	}
}

func TestSaveNormalisesAndDefaults(t *testing.T) {
	ctx, st, box := context.Background(), &memStore{}, testBox(t)

	err := SaveSettings(ctx, st, box, config.Config{}, Settings{URL: "  HTTPS://Dojo.Example/base//  ", Product: " Edge "})

	assert.NoError(t, err)
	assert.Equal(t, "HTTPS://Dojo.Example/base", st.row.URL)
	assert.Equal(t, "Edge", st.row.Product)
	assert.Equal(t, "RampartEye", st.row.ProductType)
	assert.Equal(t, "Continuous discovery", st.row.Engagement)
	assert.False(t, st.row.ManagedByEnv)
}

func TestSaveEmptyURLDisables(t *testing.T) {
	st := &memStore{}

	assert.NoError(t, SaveSettings(context.Background(), st, testBox(t), config.Config{}, Settings{}))

	assert.Equal(t, "", st.row.URL)
}

func TestRejectBadToken(t *testing.T) {
	st := &memStore{}

	err := SaveSettings(context.Background(), st, testBox(t), config.Config{}, Settings{URL: "https://d.example", Token: "a\nb"})

	assert.Error(t, err)
	assert.Equal(t, 0, st.saves)
}
