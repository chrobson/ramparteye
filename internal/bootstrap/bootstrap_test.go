package bootstrap

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ctx42/testing/pkg/assert"

	"github.com/chrobson/ramparteye/internal/config"
	"github.com/chrobson/ramparteye/internal/model"
)

// fakeStore is a hand-written Store: ctx42 mock adds ceremony without value
// for two trivial methods. Like the Postgres store, it creates all users or
// none.
type fakeStore struct {
	users    int
	made     []model.NewUser
	failOn   string
	lostRace bool
	countEr  error
}

func (f *fakeStore) CountUsers(context.Context) (int, error) { return f.users, f.countEr }

func (f *fakeStore) CreateInitialUsers(_ context.Context, users []model.NewUser) (bool, error) {
	if f.lostRace {
		return false, nil
	}
	for _, u := range users {
		if u.Login == f.failOn {
			return false, errors.New("boom")
		}
	}
	f.made = append(f.made, users...)
	f.users += len(users)
	return true, nil
}

func fakeHash(pw string) (string, error) { return "hash:" + pw, nil }

func TestFirstStartCreatesOneAdmin(t *testing.T) {
	st := &fakeStore{}
	var out bytes.Buffer

	res, err := ensure(context.Background(), st, config.Config{}, &out, fakeHash)

	assert.NoError(t, err)
	assert.Equal(t, Result{AdminCreated: true}, res)
	assert.Len(t, 1, st.made)
	assert.Equal(t, "admin", st.made[0].Login)
	assert.Equal(t, "Admin", st.made[0].Role)
	assert.True(t, st.made[0].MustChangePassword)
	assert.Equal(t, 1, strings.Count(out.String(), "admin password (shown once):"))

	pw := strings.TrimSpace(strings.SplitN(out.String(), "admin password (shown once):", 2)[1])
	assert.True(t, len(pw) >= 20)
	assert.Equal(t, "hash:"+pw, st.made[0].PasswordHash)
	assert.False(t, strings.Contains(st.made[0].PasswordHash, "admin password"))
}

func TestRestartDoesNotRecreate(t *testing.T) {
	st := &fakeStore{users: 1}
	var out bytes.Buffer

	res, err := ensure(context.Background(), st, config.Config{Demo: true}, &out, fakeHash)

	assert.NoError(t, err)
	assert.Equal(t, Result{}, res)
	assert.Len(t, 0, st.made)
	assert.Equal(t, "", out.String())
}

func TestDemoCreatesFourRoles(t *testing.T) {
	st := &fakeStore{}
	var out bytes.Buffer

	res, err := ensure(context.Background(), st, config.Config{Demo: true}, &out, fakeHash)

	assert.NoError(t, err)
	assert.Equal(t, Result{AdminCreated: true, DemoAccounts: true}, res)
	roles := map[string]string{}
	for _, u := range st.made {
		roles[u.Login] = u.Role
		assert.False(t, u.MustChangePassword)
		pw := strings.TrimPrefix(u.PasswordHash, "hash:")
		assert.True(t, strings.Contains(out.String(), u.Login))
		assert.True(t, strings.Contains(out.String(), pw))
	}
	assert.Equal(t, map[string]string{
		"admin": "Admin", "operator": "Operator", "analyst": "Analyst", "viewer": "Viewer",
	}, roles)
	assert.Equal(t, 1, strings.Count(out.String(), "shown once"))
}

func TestDemoPasswordsDiffer(t *testing.T) {
	st := &fakeStore{}
	_, err := ensure(context.Background(), st, config.Config{Demo: true}, &bytes.Buffer{}, fakeHash)
	assert.NoError(t, err)
	seen := map[string]bool{}
	for _, u := range st.made {
		seen[u.PasswordHash] = true
	}
	assert.Len(t, 4, seen)
}

func TestFailureStaysSilent(t *testing.T) {
	st := &fakeStore{failOn: "viewer"}
	var out bytes.Buffer

	_, err := ensure(context.Background(), st, config.Config{Demo: true}, &out, fakeHash)

	assert.Error(t, err)
	assert.Len(t, 0, st.made)
	assert.Equal(t, "", out.String()) // never print passwords that were not persisted
}

// Another process created the accounts between the count and the create:
// its passwords were printed there, nothing is printed here.
func TestLostFirstStartRaceStaysSilent(t *testing.T) {
	st := &fakeStore{lostRace: true}
	var out bytes.Buffer

	res, err := ensure(context.Background(), st, config.Config{}, &out, fakeHash)

	assert.NoError(t, err)
	assert.Equal(t, Result{}, res)
	assert.Equal(t, "", out.String())
}

func TestCountError(t *testing.T) {
	st := &fakeStore{countEr: errors.New("db down")}
	_, err := ensure(context.Background(), st, config.Config{}, &bytes.Buffer{}, fakeHash)
	assert.Error(t, err)
}

func TestEnsureUsesBcrypt(t *testing.T) {
	st := &fakeStore{}
	_, err := Ensure(context.Background(), st, config.Config{}, &bytes.Buffer{})
	assert.NoError(t, err)
	assert.True(t, strings.HasPrefix(st.made[0].PasswordHash, "$2a$"))
}

func TestGeneratePasswordAlphabet(t *testing.T) {
	for range 50 {
		pw, err := generatePassword()
		assert.NoError(t, err)
		assert.True(t, len(pw) >= 20)
		for _, r := range pw {
			assert.True(t, strings.ContainsRune(alphabet, r))
		}
	}
}
