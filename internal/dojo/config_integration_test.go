//go:build integration

package dojo

import (
	"context"
	"testing"

	"github.com/ctx42/testing/pkg/assert"

	"github.com/chrobson/ramparteye/internal/config"
	"github.com/chrobson/ramparteye/internal/store"
	"github.com/chrobson/ramparteye/internal/testdb"
)

func TestSaveSettingsKeepsTokenInSQL(t *testing.T) {
	ctx, box, cfg := context.Background(), testBox(t), config.Config{}
	st := store.New(testdb.New(t))

	assert.NoError(t, SaveSettings(ctx, st, box, cfg, Settings{URL: "https://d.example", Token: "first", AutoPush: true}))
	assert.NoError(t, SaveSettings(ctx, st, box, cfg, Settings{URL: "https://d2.example", Product: "P"}))

	tok, err := loadToken(ctx, st, box, cfg)
	assert.NoError(t, err)
	assert.Equal(t, "first", tok)
	have, err := LoadSettings(ctx, st, box, cfg)
	assert.NoError(t, err)
	assert.Equal(t, "https://d2.example", have.URL)
	assert.True(t, have.TokenSet)

	assert.NoError(t, SaveSettings(ctx, st, box, cfg, Settings{URL: "https://d2.example", ClearToken: true}))
	_, err = loadToken(ctx, st, box, cfg)
	assert.ErrorIs(t, ErrNoToken, err)
}
