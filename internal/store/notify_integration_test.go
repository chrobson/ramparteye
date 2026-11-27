//go:build integration

package store_test

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/ctx42/testing/pkg/assert"
	"github.com/ctx42/testing/pkg/must"

	"github.com/chrobson/ramparteye/internal/store"
)

func TestNotifyConfigSingleRow(t *testing.T) {
	s, pool := newStore(t)

	def := must.Value(s.NotifyConfig(ctx))
	assert.False(t, def.Enabled)
	assert.Nil(t, def.URLEnc)
	assert.Nil(t, def.SecretEnc)
	assert.Equal(t, "", def.Endpoint)
	assert.Equal(t, "json", def.Format)
	assert.True(t, def.OnlyChanges)
	assert.False(t, def.NotifyFailed)
	assert.Equal(t, "", def.BaseURL)

	_, err := pool.Exec(ctx, `INSERT INTO notify_config (id) VALUES (false)`)
	assert.Error(t, err)
	_, err = pool.Exec(ctx, `INSERT INTO notify_config DEFAULT VALUES`)
	assert.Error(t, err)

	in := store.NotifyConfig{Enabled: true, URLEnc: []byte("sealed-url"), Endpoint: "https://hooks.example",
		Format: "slack", SecretEnc: []byte("sealed-secret"), OnlyChanges: false, NotifyFailed: true,
		BaseURL: "https://rampart.example"}
	assert.NoError(t, s.SaveNotifyConfig(ctx, in))
	got := must.Value(s.NotifyConfig(ctx))
	assert.NotZero(t, got.UpdatedAt)
	got.UpdatedAt = in.UpdatedAt
	assert.Equal(t, in, got)

	// Nil sealed values keep the stored ones, endpoint included.
	in.URLEnc, in.SecretEnc, in.Endpoint, in.Format = nil, nil, "", "json"
	assert.NoError(t, s.SaveNotifyConfig(ctx, in))
	got = must.Value(s.NotifyConfig(ctx))
	assert.Equal(t, "json", got.Format)
	assert.Equal(t, []byte("sealed-url"), got.URLEnc)
	assert.Equal(t, "https://hooks.example", got.Endpoint)
	assert.Equal(t, []byte("sealed-secret"), got.SecretEnc)

	// A new URL replaces URL and endpoint.
	in.URLEnc, in.Endpoint = []byte("sealed-url-2"), "http://chat.example:8065"
	assert.NoError(t, s.SaveNotifyConfig(ctx, in))
	got = must.Value(s.NotifyConfig(ctx))
	assert.Equal(t, []byte("sealed-url-2"), got.URLEnc)
	assert.Equal(t, "http://chat.example:8065", got.Endpoint)

	// Clear flags remove the values.
	assert.NoError(t, s.SaveNotifyConfig(ctx, store.NotifyConfig{Format: "json", ClearURL: true, ClearSecret: true}))
	got = must.Value(s.NotifyConfig(ctx))
	assert.Nil(t, got.URLEnc)
	assert.Equal(t, "", got.Endpoint)
	assert.Nil(t, got.SecretEnc)

	var n int
	must.Nil(pool.QueryRow(ctx, `SELECT count(*) FROM notify_config`).Scan(&n))
	assert.Equal(t, 1, n)
}

func TestNotifyConfigErrorsHideSecrets(t *testing.T) {
	s, _ := newStore(t)

	// A format violating the CHECK constraint makes PostgreSQL report the
	// failing row, sealed values included (as hex), in the error detail.
	err := s.SaveNotifyConfig(ctx, store.NotifyConfig{Format: "xml", URLEnc: []byte("URLMARKER"),
		SecretEnc: []byte("SECRETMARKER")})

	assert.Error(t, err)
	msg := errorText(err)
	for _, m := range []string{"URLMARKER", "SECRETMARKER"} {
		assert.NotContain(t, m, msg)
		assert.NotContain(t, hex.EncodeToString([]byte(m)), msg)
	}
}

func TestNotifyConfigMissingRow(t *testing.T) {
	s, pool := newStore(t)
	must.Value(pool.Exec(ctx, `DELETE FROM notify_config`))

	_, err := s.NotifyConfig(ctx)
	assert.ErrorIs(t, store.ErrNotFound, err)

	err = s.SaveNotifyConfig(ctx, store.NotifyConfig{Format: "json"})
	assert.ErrorIs(t, store.ErrNotFound, err)
}

func TestNotifyDeliveries(t *testing.T) {
	s, pool := newStore(t)
	run := insertRun(t, pool, "scan", "done")
	gone := int64(999999)
	status := 204
	assert.Len(t, 0, must.Value(s.NotifyDeliveries(ctx, 10)))

	assert.NoError(t, s.RecordNotifyDelivery(ctx, store.NotifyDelivery{RunID: &run, Trigger: "auto",
		Event: "scan.finished", Endpoint: "https://hooks.example", Attempts: 1, Status: &status, OK: true}))
	bad := 503
	assert.NoError(t, s.RecordNotifyDelivery(ctx, store.NotifyDelivery{Trigger: "test", Event: "test",
		Endpoint: "https://hooks.example", Attempts: 3, Status: &bad, Error: "HTTP 503"}))
	assert.NoError(t, s.RecordNotifyDelivery(ctx, store.NotifyDelivery{RunID: &gone, Trigger: "auto",
		Event: "scan.failed", Attempts: 1, Error: strings.Repeat("x", 2000)}))
	assert.Error(t, s.RecordNotifyDelivery(ctx, store.NotifyDelivery{Trigger: "bogus"}))

	ds := must.Value(s.NotifyDeliveries(ctx, 10))
	assert.Len(t, 3, ds)
	assert.Nil(t, ds[0].RunID) // unknown run stored as NULL
	assert.Nil(t, ds[0].Status)
	assert.Equal(t, 500, len(ds[0].Error)) // bounded on write
	assert.Equal(t, "test", ds[1].Trigger)
	assert.Nil(t, ds[1].RunID)
	assert.Equal(t, 503, *ds[1].Status)
	assert.Equal(t, 3, ds[1].Attempts)
	assert.False(t, ds[1].OK)
	d := ds[2]
	assert.Equal(t, run, *d.RunID)
	assert.Equal(t, "auto", d.Trigger)
	assert.Equal(t, "scan.finished", d.Event)
	assert.Equal(t, "https://hooks.example", d.Endpoint)
	assert.Equal(t, 204, *d.Status)
	assert.True(t, d.OK)
	assert.NotZero(t, d.At)
	assert.Len(t, 1, must.Value(s.NotifyDeliveries(ctx, 1)))
}
