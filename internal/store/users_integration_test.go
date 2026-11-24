//go:build integration

package store_test

import (
	"bytes"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/ctx42/testing/pkg/assert"
	"github.com/ctx42/testing/pkg/must"

	"github.com/chrobson/ramparteye/internal/bootstrap"
	"github.com/chrobson/ramparteye/internal/config"
	"github.com/chrobson/ramparteye/internal/model"
	"github.com/chrobson/ramparteye/internal/store"
)

const secretHash = "$2a$10$SECRETHASHMARKERxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

func TestBuiltinRoles(t *testing.T) {
	s, _ := newStore(t)

	roles, err := s.Roles(ctx)

	assert.NoError(t, err)
	got := map[string][]string{}
	for _, r := range roles {
		assert.True(t, r.Builtin)
		got[r.Name] = r.Perms
	}
	assert.Equal(t, map[string][]string{
		"Admin": {"export", "results.edit", "results.read", "scans.run", "settings.admin",
			"signatures.write", "targets.read", "targets.write", "users.admin"},
		"Operator": {"export", "results.edit", "results.read", "scans.run", "signatures.write",
			"targets.read", "targets.write"},
		"Analyst": {"export", "results.edit", "results.read", "targets.read"},
		"Viewer":  {"results.read", "targets.read"},
	}, got)
}

func TestCreateInitialUsers(t *testing.T) {
	s, _ := newStore(t)
	users := []model.NewUser{
		{Login: "admin", PasswordHash: "h1", Role: "Admin", MustChangePassword: true},
		{Login: "viewer", PasswordHash: "h2", Role: "Viewer"},
	}

	created, err := s.CreateInitialUsers(ctx, users)

	assert.NoError(t, err)
	assert.True(t, created)
	assert.Equal(t, 2, must.Value(s.CountUsers(ctx)))
	admin := must.Value(s.UserByLogin(ctx, "admin"))
	assert.Equal(t, "Admin", admin.RoleName)
	assert.Equal(t, "h1", admin.PasswordHash)
	assert.True(t, admin.MustChangePassword)
	assert.Has(t, "users.admin", admin.Perms)
	viewer := must.Value(s.UserByLogin(ctx, "viewer"))
	assert.False(t, viewer.MustChangePassword)
	assert.Equal(t, []string{"results.read", "targets.read"}, viewer.Perms)

	audit := must.Value(s.AuditEntries(ctx, 10))
	assert.Len(t, 2, audit)
	assert.Equal(t, "user.seed", audit[0].Action)
	assert.NotContain(t, "h1", audit[0].Details+audit[1].Details)
}

func TestCreateInitialUsersOnlyWhenEmpty(t *testing.T) {
	s, _ := newStore(t)
	must.Value(s.CreateInitialUsers(ctx, []model.NewUser{{Login: "admin", PasswordHash: "h", Role: "Admin"}}))

	created, err := s.CreateInitialUsers(ctx, []model.NewUser{{Login: "other", PasswordHash: "h", Role: "Admin"}})

	assert.NoError(t, err)
	assert.False(t, created)
	assert.Equal(t, 1, must.Value(s.CountUsers(ctx)))
}

func TestCreateInitialUsersIsAtomic(t *testing.T) {
	s, _ := newStore(t)
	users := []model.NewUser{
		{Login: "admin", PasswordHash: secretHash, Role: "Admin"},
		{Login: "viewer", PasswordHash: secretHash, Role: "NoSuchRole"},
	}

	created, err := s.CreateInitialUsers(ctx, users)

	assert.ErrorIs(t, store.ErrRoleNotFound, err)
	assert.False(t, created)
	assert.Equal(t, 0, must.Value(s.CountUsers(ctx)))
}

func TestCreateInitialUsersConcurrent(t *testing.T) {
	s, _ := newStore(t)
	var wg sync.WaitGroup
	results := make([]bool, 4)
	errs := make([]error, 4)
	for i := range results {
		wg.Go(func() {
			results[i], errs[i] = s.CreateInitialUsers(ctx, []model.NewUser{
				{Login: fmt.Sprintf("admin%d", i), PasswordHash: "h", Role: "Admin"},
			})
		})
	}
	wg.Wait()

	n := 0
	for i := range results {
		assert.NoError(t, errs[i])
		if results[i] {
			n++
		}
	}
	assert.Equal(t, 1, n)
	assert.Equal(t, 1, must.Value(s.CountUsers(ctx)))
}

func TestUserErrorsHideHash(t *testing.T) {
	s, _ := newStore(t)

	// An empty login violates a CHECK constraint; PostgreSQL reports the
	// failing row, hash included, in the error detail.
	_, err := s.CreateUser(ctx, model.NewUser{Login: "", PasswordHash: secretHash, Role: "Admin"})

	assert.Error(t, err)
	assert.NotContain(t, "SECRETHASHMARKER", errorText(err))

	must.Value(s.CreateUser(ctx, model.NewUser{Login: "dup", PasswordHash: "h", Role: "Admin"}))
	_, err = s.CreateUser(ctx, model.NewUser{Login: "dup", PasswordHash: secretHash, Role: "Admin"})
	assert.ErrorIs(t, store.ErrLoginTaken, err)
	assert.NotContain(t, "SECRETHASHMARKER", errorText(err))
}

func TestUsersAndRoles(t *testing.T) {
	s, _ := newStore(t)
	id := must.Value(s.CreateUser(ctx, model.NewUser{Login: "ann", PasswordHash: "h", Role: "Viewer"}))

	byID := must.Value(s.UserByID(ctx, id))
	assert.Equal(t, "ann", byID.Login)
	_, err := s.UserByLogin(ctx, "nobody")
	assert.ErrorIs(t, store.ErrUserNotFound, err)

	roleID := must.Value(s.CreateRole(ctx, "Auditor", []string{"results.read", "export"}))
	assert.NoError(t, s.SetUserRole(ctx, id, roleID))
	u := must.Value(s.UserByID(ctx, id))
	assert.Equal(t, "Auditor", u.RoleName)
	assert.Equal(t, []string{"export", "results.read"}, u.Perms)
	assert.ErrorIs(t, store.ErrUserNotFound, s.SetUserRole(ctx, -1, roleID))

	assert.NoError(t, s.SetPassword(ctx, id, "h2", true))
	u = must.Value(s.UserByID(ctx, id))
	assert.Equal(t, "h2", u.PasswordHash)
	assert.True(t, u.MustChangePassword)

	_, err = s.DeleteRole(ctx, roleID)
	assert.ErrorIs(t, store.ErrRoleInUse, err)
	adminID := must.Value(s.RoleIDByName(ctx, "Admin"))
	_, err = s.DeleteRole(ctx, adminID)
	assert.ErrorIs(t, store.ErrRoleBuiltin, err)
	viewerID := must.Value(s.RoleIDByName(ctx, "Viewer"))
	assert.NoError(t, s.SetUserRole(ctx, id, viewerID))
	name, err := s.DeleteRole(ctx, roleID)
	assert.NoError(t, err)
	assert.Equal(t, "Auditor", name)
	_, err = s.RoleIDByName(ctx, "Auditor")
	assert.ErrorIs(t, store.ErrRoleNotFound, err)

	users := must.Value(s.Users(ctx))
	assert.Len(t, 1, users)
}

func TestSessions(t *testing.T) {
	s, _ := newStore(t)
	id := must.Value(s.CreateUser(ctx, model.NewUser{Login: "ann", PasswordHash: "h", Role: "Analyst"}))
	live, old := []byte("live-token-hash"), []byte("old-token-hash")
	assert.NoError(t, s.CreateSession(ctx, live, id, time.Now().Add(time.Hour)))
	assert.NoError(t, s.CreateSession(ctx, old, id, time.Now().Add(-time.Hour)))

	u, err := s.SessionUser(ctx, live)
	assert.NoError(t, err)
	assert.Equal(t, "ann", u.Login)
	_, err = s.SessionUser(ctx, old)
	assert.ErrorIs(t, store.ErrUserNotFound, err)

	assert.Equal(t, int64(1), must.Value(s.DeleteExpiredSessions(ctx)))
	assert.NoError(t, s.DeleteSession(ctx, live))
	_, err = s.SessionUser(ctx, live)
	assert.ErrorIs(t, store.ErrUserNotFound, err)

	assert.NoError(t, s.CreateSession(ctx, live, id, time.Now().Add(time.Hour)))
	assert.NoError(t, s.DeleteUserSessions(ctx, id))
	_, err = s.SessionUser(ctx, live)
	assert.ErrorIs(t, store.ErrUserNotFound, err)
}

func TestAuditAndSecrets(t *testing.T) {
	s, _ := newStore(t)
	id := must.Value(s.CreateUser(ctx, model.NewUser{Login: "ann", PasswordHash: "h", Role: "Admin"}))
	assert.NoError(t, s.InsertAudit(ctx, &id, "targets.import", "targets", map[string]int{"inserted": 2}))
	assert.NoError(t, s.InsertAudit(ctx, nil, "login.failed", "user:x", nil))

	entries := must.Value(s.AuditEntries(ctx, 10))
	assert.Len(t, 2, entries)
	assert.Equal(t, "login.failed", entries[0].Action)
	assert.Equal(t, "", entries[0].Login)
	assert.Equal(t, "ann", entries[1].Login)
	assert.Equal(t, `{"inserted": 2}`, entries[1].Details)

	_, err := s.Secret(ctx, "dojo")
	assert.ErrorIs(t, store.ErrSecretNotFound, err)
	assert.NoError(t, s.PutSecret(ctx, "dojo", []byte{1, 2}))
	assert.NoError(t, s.PutSecret(ctx, "dojo", []byte{3}))
	assert.Equal(t, []byte{3}, must.Value(s.Secret(ctx, "dojo")))
}

func TestBootstrapEnsureWithStore(t *testing.T) {
	s, _ := newStore(t)
	var out bytes.Buffer

	res, err := bootstrap.Ensure(ctx, s, config.Config{}, &out)
	assert.NoError(t, err)
	assert.True(t, res.AdminCreated)
	assert.Contain(t, "admin password (shown once):", out.String())
	admin := must.Value(s.UserByLogin(ctx, "admin"))
	assert.True(t, admin.MustChangePassword)
	assert.Equal(t, "Admin", admin.RoleName)

	out.Reset()
	res, err = bootstrap.Ensure(ctx, s, config.Config{}, &out) // restart
	assert.NoError(t, err)
	assert.False(t, res.AdminCreated)
	assert.Equal(t, "", out.String())
	assert.Equal(t, 1, must.Value(s.CountUsers(ctx)))
}

func TestSessionUserAtUsesGivenClock(t *testing.T) {
	s, _ := newStore(t)
	id := must.Value(s.CreateUser(ctx, model.NewUser{Login: "bob", PasswordHash: "h", Role: "Viewer"}))
	exp := time.Now().Add(time.Hour)
	assert.NoError(t, s.CreateSession(ctx, []byte("tok"), id, exp))

	u, err := s.SessionUserAt(ctx, []byte("tok"), exp.Add(-time.Minute))
	assert.NoError(t, err)
	assert.Equal(t, "bob", u.Login)
	_, err = s.SessionUserAt(ctx, []byte("tok"), exp.Add(time.Minute))
	assert.ErrorIs(t, store.ErrUserNotFound, err)
}
