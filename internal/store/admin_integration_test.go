//go:build integration

package store_test

import (
	"testing"
	"time"

	"github.com/ctx42/testing/pkg/assert"
	"github.com/ctx42/testing/pkg/must"

	"github.com/chrobson/ramparteye/internal/model"
	"github.com/chrobson/ramparteye/internal/store"
)

func TestSetUserDisabled(t *testing.T) {
	s, _ := newStore(t)
	id := must.Value(s.CreateUser(ctx, model.NewUser{Login: "ann", PasswordHash: "h", Role: "Viewer"}))
	tok := []byte("token-hash")
	assert.NoError(t, s.CreateSession(ctx, tok, id, time.Now().Add(time.Hour)))

	assert.NoError(t, s.SetUserDisabled(ctx, id, true))

	u := must.Value(s.UserByLogin(ctx, "ann"))
	assert.True(t, u.Disabled)
	_, err := s.SessionUser(ctx, tok)
	assert.ErrorIs(t, store.ErrUserNotFound, err)
	assert.ErrorIs(t, store.ErrUserNotFound, s.SetUserDisabled(ctx, -1, true))

	assert.NoError(t, s.SetUserDisabled(ctx, id, false))
	assert.False(t, must.Value(s.UserByID(ctx, id)).Disabled)
	_, err = s.SessionUser(ctx, tok)
	assert.NoError(t, err)
}

func TestAuditQuery(t *testing.T) {
	s, _ := newStore(t)
	id := must.Value(s.CreateUser(ctx, model.NewUser{Login: "ann", PasswordHash: "h", Role: "Admin"}))
	for i := 0; i < 3; i++ {
		assert.NoError(t, s.InsertAudit(ctx, &id, "user.create", "user:x", nil))
	}
	assert.NoError(t, s.InsertAudit(ctx, nil, "login.failed", "user:y", nil))

	all := must.Value(s.AuditQuery(ctx, store.AuditFilter{Limit: 10}))
	assert.Len(t, 4, all)
	assert.Equal(t, "login.failed", all[0].Action)

	page := must.Value(s.AuditQuery(ctx, store.AuditFilter{Action: "user.create", Limit: 2, Offset: 2}))
	assert.Len(t, 1, page)
	assert.Equal(t, "user.create", page[0].Action)
	assert.Equal(t, "ann", page[0].Login)
	assert.Equal(t, all[3].ID, page[0].ID)

	assert.Equal(t, []string{"login.failed", "user.create"}, must.Value(s.AuditActions(ctx)))
}

func TestBacktestHistory(t *testing.T) {
	s, pool := newStore(t)
	old := insertRun(t, pool, "scan", "done")
	insertService(t, pool, old, "10.0.0.1", 22)
	failed := insertRun(t, pool, "scan", "failed")
	insertService(t, pool, failed, "10.0.0.9", 80)
	run := insertRun(t, pool, "scan", "done")
	web := insertService(t, pool, run, "10.0.0.2", 80)
	insertService(t, pool, run, "10.0.0.3", 443)
	assert.NoError(t, s.SaveHTTPObs(ctx, model.HTTPObs{ServiceID: web, URL: "http://10.0.0.2/", Status: 200,
		Title: "Login", Headers: map[string][]string{"Server": {"nginx"}}}))

	got := must.Value(s.BacktestHistory(ctx, 1))

	assert.Len(t, 2, got)
	assert.Equal(t, run, got[0].Service.RunID)
	assert.Equal(t, addr("10.0.0.2"), got[0].Service.Key.IP)
	assert.Equal(t, uint16(80), got[0].Service.Key.Port)
	assert.Equal(t, "Login", got[0].HTTP.Title)
	assert.Equal(t, 200, got[0].HTTP.Status)
	assert.Equal(t, []string{"nginx"}, got[0].HTTP.Headers["Server"])
	assert.Equal(t, "", got[1].HTTP.URL)

	assert.Len(t, 3, must.Value(s.BacktestHistory(ctx, 5)))
}
