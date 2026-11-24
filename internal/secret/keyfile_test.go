package secret

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ctx42/testing/pkg/assert"
)

func TestLoadOrCreateIdempotent(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "secrets")

	k1, created, err := LoadOrCreate(dir, "key", 32, nil)
	assert.NoError(t, err)
	assert.True(t, created)
	assert.Len(t, 32, k1)

	k2, created, err := LoadOrCreate(dir, "key", 32, nil)
	assert.NoError(t, err)
	assert.False(t, created)
	assert.Equal(t, k1, k2)
}

func TestKeyFilePermissions(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "secrets")

	_, _, err := LoadOrCreate(dir, "key", 32, nil)
	assert.NoError(t, err)

	fi, err := os.Stat(filepath.Join(dir, "key"))
	assert.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), fi.Mode().Perm())
	di, err := os.Stat(dir)
	assert.NoError(t, err)
	assert.Equal(t, os.FileMode(0o700), di.Mode().Perm())
	ents, _ := os.ReadDir(dir)
	assert.Len(t, 1, ents) // no temp files left behind
}

func TestEnvKeyOverrides(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "secrets")
	override := make([]byte, 32)
	override[0] = 9

	k, created, err := LoadOrCreate(dir, "key", 32, override)

	assert.NoError(t, err)
	assert.False(t, created)
	assert.Equal(t, override, k)
	_, statErr := os.Stat(dir)
	assert.True(t, os.IsNotExist(statErr)) // nothing written
}

func TestLoadOrCreateRefusesWrongSize(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "key")
	assert.NoError(t, os.WriteFile(path, []byte("short"), 0o600))

	_, _, err := LoadOrCreate(dir, "key", 32, nil)

	assert.Error(t, err)
	b, _ := os.ReadFile(path)
	assert.Equal(t, "short", string(b)) // not overwritten
}

func TestLoadOrCreateRejectsBadArgs(t *testing.T) {
	_, _, err := LoadOrCreate(t.TempDir(), "../key", 32, nil)
	assert.Error(t, err)
	_, _, err = LoadOrCreate(t.TempDir(), "key", 0, nil)
	assert.Error(t, err)
}
