//go:build integration

package store_test

import (
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/ctx42/testing/pkg/assert"
	"github.com/ctx42/testing/pkg/must"

	"github.com/chrobson/ramparteye/internal/store"
)

func TestDojoConfigSingleRow(t *testing.T) {
	s, pool := newStore(t)

	def := must.Value(s.DojoConfig(ctx))
	assert.Equal(t, "", def.URL)
	assert.Nil(t, def.TokenEnc)
	assert.Equal(t, "RampartEye", def.ProductType)
	assert.Equal(t, "Continuous discovery", def.Engagement)
	assert.True(t, def.AutoPush)
	assert.False(t, def.CloseMissing)
	assert.False(t, def.ManagedByEnv)

	_, err := pool.Exec(ctx, `INSERT INTO dojo_config (id) VALUES (false)`)
	assert.Error(t, err)
	_, err = pool.Exec(ctx, `INSERT INTO dojo_config DEFAULT VALUES`)
	assert.Error(t, err)

	in := store.DojoConfig{URL: "https://dojo.example", TokenEnc: []byte("sealed"), ProductType: "PT",
		Product: "P", Engagement: "E", AutoPush: false, CloseMissing: true, ManagedByEnv: true}
	assert.NoError(t, s.SaveDojoConfig(ctx, in))
	got := must.Value(s.DojoConfig(ctx))
	assert.NotZero(t, got.UpdatedAt)
	got.UpdatedAt = in.UpdatedAt
	assert.Equal(t, in, got)

	// A nil token keeps the stored one.
	in.TokenEnc, in.URL = nil, "https://dojo2.example"
	assert.NoError(t, s.SaveDojoConfig(ctx, in))
	got = must.Value(s.DojoConfig(ctx))
	assert.Equal(t, "https://dojo2.example", got.URL)
	assert.Equal(t, []byte("sealed"), got.TokenEnc)

	var n int
	must.Nil(pool.QueryRow(ctx, `SELECT count(*) FROM dojo_config`).Scan(&n))
	assert.Equal(t, 1, n)
}

func TestDojoConfigErrorsHideToken(t *testing.T) {
	s, _ := newStore(t)

	// A URL violating the CHECK constraint makes PostgreSQL report the
	// failing row, sealed token included (as hex), in the error detail.
	err := s.SaveDojoConfig(ctx, store.DojoConfig{URL: "ftp://x", TokenEnc: []byte("TOKENMARKER")})

	assert.Error(t, err)
	msg := errorText(err)
	assert.NotContain(t, "TOKENMARKER", msg)
	assert.NotContain(t, hex.EncodeToString([]byte("TOKENMARKER")), msg)
}

func TestDojoPushes(t *testing.T) {
	s, pool := newStore(t)
	run := insertRun(t, pool, "scan", "done")
	testID := int64(7)
	assert.NoError(t, s.RecordDojoPush(ctx, store.DojoPush{RunID: &run, Trigger: "auto", Endpoint: "reimport-scan",
		Findings: 36, Added: 2, Closed: 1, TestID: &testID, OK: true, Statistics: json.RawMessage(`{"a": 1}`)}))
	assert.NoError(t, s.RecordDojoPush(ctx, store.DojoPush{RunID: &run, Trigger: "manual", OK: false, Error: "401 Unauthorized"}))
	assert.Error(t, s.RecordDojoPush(ctx, store.DojoPush{Trigger: "bogus"}))

	pushes := must.Value(s.DojoPushes(ctx, 10))
	assert.Len(t, 2, pushes)
	assert.False(t, pushes[0].OK)
	assert.Equal(t, "401 Unauthorized", pushes[0].Error)
	assert.Equal(t, json.RawMessage(`{}`), pushes[0].Statistics)
	p := pushes[1]
	assert.Equal(t, run, *p.RunID)
	assert.Equal(t, "auto", p.Trigger)
	assert.Equal(t, 36, p.Findings)
	assert.Equal(t, 2, p.Added)
	assert.Equal(t, 1, p.Closed)
	assert.Equal(t, testID, *p.TestID)
	assert.True(t, p.OK)
	assert.NotZero(t, p.At)
	assert.Len(t, 1, must.Value(s.DojoPushes(ctx, 1)))
}

func TestDojoConfigMissingRow(t *testing.T) {
	s, pool := newStore(t)
	must.Value(pool.Exec(ctx, `DELETE FROM dojo_config`))

	_, err := s.DojoConfig(ctx)
	assert.ErrorIs(t, store.ErrNotFound, err)

	err = s.SaveDojoConfig(ctx, store.DojoConfig{URL: "https://dojo.example"})
	assert.ErrorIs(t, store.ErrNotFound, err)
}
