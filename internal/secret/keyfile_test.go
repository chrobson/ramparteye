package secret

import (
	"os"
	"path/filepath"
	"sync"
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

func TestLoadOrCreateConcurrent(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "secrets")
	const n = 16
	keys := make([][]byte, n)
	createdFlags := make([]bool, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			keys[i], createdFlags[i], errs[i] = LoadOrCreate(dir, "key", 32, nil)
		}()
	}
	wg.Wait()

	creators := 0
	onDisk, err := os.ReadFile(filepath.Join(dir, "key"))
	assert.NoError(t, err)
	for i := range n {
		assert.NoError(t, errs[i])
		assert.Equal(t, onDisk, keys[i])
		if createdFlags[i] {
			creators++
		}
	}
	assert.Equal(t, 1, creators)
}

func TestLoadOrCreateTightensDirMode(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "vol")
	assert.NoError(t, os.Mkdir(dir, 0o755))
	assert.NoError(t, os.Chmod(dir, 0o755))

	_, _, err := LoadOrCreate(dir, "key", 32, nil)

	assert.NoError(t, err)
	di, err := os.Stat(dir)
	assert.NoError(t, err)
	assert.Equal(t, os.FileMode(0o700), di.Mode().Perm())
}

func TestLoadOrCreateRefusesLooseMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "key")
	assert.NoError(t, os.WriteFile(path, make([]byte, 32), 0o600))
	assert.NoError(t, os.Chmod(path, 0o644))

	_, _, err := LoadOrCreate(dir, "key", 32, nil)

	assert.ErrorContain(t, "0644", err)
}

func TestLoadOrCreateRefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(t.TempDir(), "real")
	assert.NoError(t, os.WriteFile(target, make([]byte, 32), 0o600))
	assert.NoError(t, os.Symlink(target, filepath.Join(dir, "key")))

	_, _, err := LoadOrCreate(dir, "key", 32, nil)

	assert.ErrorContain(t, "not a regular file", err)
}

func TestLoadOrCreateRejectsEmptyDir(t *testing.T) {
	_, _, err := LoadOrCreate("", "key", 32, nil)
	assert.Error(t, err)
}
