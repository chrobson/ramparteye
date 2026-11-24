package bootstrap

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ctx42/testing/pkg/assert"

	"github.com/chrobson/ramparteye/internal/config"
)

type created struct {
	Login, Hash, Role string
	MustChange        bool
}

// fakeStore is a hand-written Store: ctx42 mock adds ceremony without value
// for two trivial methods.
type fakeStore struct {
	users   int
	made    []created
	failOn  string
	countEr error
}

func (f *fakeStore) CountUsers(context.Context) (int, error) { return f.users, f.countEr }

func (f *fakeStore) CreateUser(_ context.Context, login, hash, role string, must bool) error {
	if login == f.failOn {
		return errors.New("boom")
	}
	f.made = append(f.made, created{login, hash, role, must})
	f.users++
	return nil
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
	assert.True(t, st.made[0].MustChange)
	assert.Equal(t, 1, strings.Count(out.String(), "admin password (shown once):"))

	pw := strings.TrimSpace(strings.SplitN(out.String(), "admin password (shown once):", 2)[1])
	assert.True(t, len(pw) >= 20)
	assert.Equal(t, "hash:"+pw, st.made[0].Hash)
	assert.False(t, strings.Contains(st.made[0].Hash, "admin password"))
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
		assert.False(t, u.MustChange)
		pw := strings.TrimPrefix(u.Hash, "hash:")
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
		seen[u.Hash] = true
	}
	assert.Len(t, 4, seen)
}

func TestFailureStaysSilent(t *testing.T) {
	st := &fakeStore{failOn: "viewer"}
	var out bytes.Buffer

	_, err := ensure(context.Background(), st, config.Config{Demo: true}, &out, fakeHash)

	assert.Error(t, err)
	assert.Equal(t, "", out.String()) // never print passwords that were not persisted
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
	assert.True(t, strings.HasPrefix(st.made[0].Hash, "$2a$"))
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
