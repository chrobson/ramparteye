package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/ctx42/testing/pkg/assert"
	"github.com/ctx42/testing/pkg/must"

	"github.com/chrobson/ramparteye/internal/secret"
)

const (
	hookURL    = "https://Hooks.Example/services/T000/B000/SECRETPATH"
	hookSecret = "s1gning-SECRET-value"
)

func testBox(t *testing.T) *secret.Box {
	t.Helper()
	return must.Value(secret.NewBox(bytes.Repeat([]byte{3}, 32)))
}

func validSettings() Settings {
	return Settings{Enabled: true, URL: hookURL, Format: FormatSlack, Secret: hookSecret, OnlyChanges: true,
		NotifyFailed: true, BaseURL: "HTTPS://Rampart.Example/ui/"}
}

func TestSaveSettingsSealsCredentials(t *testing.T) {
	ctx, st, box := context.Background(), newMemStore(), testBox(t)

	assert.NoError(t, SaveSettings(ctx, st, box, validSettings()))

	row := st.cfg
	assert.True(t, row.Enabled)
	assert.Equal(t, "slack", row.Format)
	assert.Equal(t, "https://hooks.example", row.Endpoint)
	assert.Equal(t, "https://rampart.example/ui", row.BaseURL)
	assert.True(t, row.OnlyChanges)
	assert.True(t, row.NotifyFailed)
	assert.NotEmpty(t, row.URLEnc)
	assert.NotEmpty(t, row.SecretEnc)
	for _, b := range [][]byte{row.URLEnc, row.SecretEnc} {
		assert.False(t, bytes.Contains(b, []byte("SECRET")))
	}
	// Bound to their columns: the sealed URL does not open as the secret.
	_, err := box.Open(row.URLEnc, secretAAD)
	assert.Error(t, err)

	got := must.Value(LoadSettings(ctx, st))
	assert.Equal(t, "", got.URL)
	assert.Equal(t, "", got.Secret)
	assert.True(t, got.URLSet)
	assert.True(t, got.SecretSet)
	assert.Equal(t, "https://hooks.example", got.Endpoint)
	assert.Equal(t, "https://rampart.example/ui", got.BaseURL)

	tg := must.Value(loadTarget(ctx, st, box))
	assert.Equal(t, "https://hooks.example/services/T000/B000/SECRETPATH", tg.url.String())
	assert.Equal(t, hookSecret, tg.secret)
}

func TestSaveSettingsKeepsAndClearsCredentials(t *testing.T) {
	ctx, st, box := context.Background(), newMemStore(), testBox(t)
	must.Nil(SaveSettings(ctx, st, box, validSettings()))
	sealedURL := st.cfg.URLEnc

	// Empty fields keep the stored values.
	s := validSettings()
	s.URL, s.Secret, s.Format = "", "", FormatJSON
	assert.NoError(t, SaveSettings(ctx, st, box, s))
	assert.Equal(t, sealedURL, st.cfg.URLEnc)
	assert.NotEmpty(t, st.cfg.SecretEnc)
	assert.Equal(t, "json", st.cfg.Format)

	// The secret can be removed on its own.
	s.ClearSecret = true
	assert.NoError(t, SaveSettings(ctx, st, box, s))
	assert.Empty(t, st.cfg.SecretEnc)
	assert.NotEmpty(t, st.cfg.URLEnc)

	// Removing the URL needs notifications off.
	s = Settings{Enabled: true, ClearURL: true, Format: FormatJSON}
	assert.ErrorIs(t, ErrNoURL, SaveSettings(ctx, st, box, s))
	s.Enabled = false
	assert.NoError(t, SaveSettings(ctx, st, box, s))
	assert.Empty(t, st.cfg.URLEnc)
	assert.Equal(t, "", st.cfg.Endpoint)
	assert.False(t, must.Value(LoadSettings(ctx, st)).URLSet)
}

func TestSaveSettingsValidation(t *testing.T) {
	ctx, box := context.Background(), testBox(t)
	for name, s := range map[string]Settings{
		"enabled without url":  {Enabled: true, Format: FormatJSON},
		"bad format":           {URL: hookURL, Format: "xml"},
		"url set and cleared":  {URL: hookURL, ClearURL: true, Format: FormatJSON},
		"secret set and clear": {URL: hookURL, Secret: "x", ClearSecret: true, Format: FormatJSON},
		"ftp url":              {URL: "ftp://hooks.example/SECRETPATH", Format: FormatJSON},
		"url with credentials": {URL: "https://user:SECRETPW@hooks.example/x", Format: FormatJSON},
		"url with fragment":    {URL: "https://hooks.example/x#SECRETFRAG", Format: FormatJSON},
		"url too long":         {URL: "https://hooks.example/" + strings.Repeat("S", 2100), Format: FormatJSON},
		"secret control char":  {URL: hookURL, Secret: "SECRET\x01", Format: FormatJSON},
		"secret too long":      {URL: hookURL, Secret: strings.Repeat("S", 513), Format: FormatJSON},
		"base url with query":  {URL: hookURL, BaseURL: "https://rampart.example/?SECRETQ=1", Format: FormatJSON},
	} {
		st := newMemStore()
		err := SaveSettings(ctx, st, box, s)
		assert.Error(t, err, name)
		assert.Equal(t, 0, st.saves, name)
		assert.False(t, strings.Contains(err.Error(), "SECRET"), name+": "+err.Error())
	}

	// A query is part of many webhook URLs (signed flow URLs).
	st := newMemStore()
	assert.NoError(t, SaveSettings(ctx, st, box, Settings{URL: "https://flow.example/run?sig=abc", Format: FormatJSON}))
	// http is allowed: internal chat servers often have no TLS.
	assert.NoError(t, SaveSettings(ctx, st, box, Settings{URL: "http://chat.lan:8065/hooks/x", Format: FormatJSON}))
	assert.Equal(t, "http://chat.lan:8065", st.cfg.Endpoint)
	// No key, no credentials.
	assert.Error(t, SaveSettings(ctx, newMemStore(), nil, Settings{URL: hookURL, Format: FormatJSON}))
}

func TestLoadSettingsDefaults(t *testing.T) {
	st := newMemStore()
	st.cfg = nil

	got := must.Value(LoadSettings(context.Background(), st))

	assert.Equal(t, Settings{Format: FormatJSON, OnlyChanges: true}, got)

	st.cfgErr = errors.New("db down")
	_, err := LoadSettings(context.Background(), st)
	assert.Error(t, err)
}

func TestLoadTargetUnavailable(t *testing.T) {
	ctx, st := context.Background(), newMemStore()
	must.Nil(SaveSettings(ctx, st, testBox(t), validSettings()))

	_, err := loadTarget(ctx, st, must.Value(secret.NewBox(bytes.Repeat([]byte{9}, 32))))
	assert.ErrorIs(t, ErrURLUnavailable, err)
	assert.ErrorContain(t, "re-enter it in Settings", err)
	_, err = loadTarget(ctx, st, nil)
	assert.ErrorIs(t, ErrURLUnavailable, err)

	_, err = loadTarget(ctx, newMemStore(), testBox(t))
	assert.ErrorIs(t, ErrNotConfigured, err)
}

func TestSettingsRedactCredentials(t *testing.T) {
	s := validSettings()
	for _, out := range []string{
		fmt.Sprintf("%v", s), fmt.Sprintf("%+v", s), fmt.Sprintf("%#v", s), fmt.Sprint(&s),
		string(must.Value(json.Marshal(s))),
	} {
		assert.False(t, strings.Contains(out, "SECRET"), out)
	}
	assert.Contain(t, "Rampart.Example", fmt.Sprintf("%+v", s))
}

// testBoxOther is a box with another key: values sealed by testBox do not
// open with it.
func testBoxOther(t *testing.T) *secret.Box {
	t.Helper()
	return must.Value(secret.NewBox(bytes.Repeat([]byte{9}, 32)))
}
