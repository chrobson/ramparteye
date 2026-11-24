package secret

import (
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// LoadOrCreate returns the key stored in dir/name, generating size random
// bytes on first use. A non-empty override (from RAMPART_SECRET_KEY) wins and
// touches nothing on disk. An existing file of the wrong size, a non-regular
// file or one readable by group/others is an error and is never overwritten,
// so a restart can never silently rotate a key. Concurrent first starts agree
// on one key: exactly one caller sees created == true.
func LoadOrCreate(dir, name string, size int, override []byte) (key []byte, created bool, err error) {
	if len(override) > 0 {
		if len(override) != size {
			return nil, false, fmt.Errorf("secret: override key must be %d bytes, got %d", size, len(override))
		}
		return append([]byte(nil), override...), false, nil
	}
	if size <= 0 {
		return nil, false, errors.New("secret: key size must be positive")
	}
	if dir == "" {
		return nil, false, errors.New("secret: directory is required")
	}
	if name == "" || name != filepath.Base(name) || name == "." || name == ".." {
		return nil, false, fmt.Errorf("secret: invalid key file name %q", name)
	}
	path := filepath.Join(dir, name)

	key, err = readKey(path, size)
	if err == nil {
		return key, false, nil
	}
	if !os.IsNotExist(err) {
		return nil, false, err
	}

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, false, fmt.Errorf("secret: create dir: %w", err)
	}
	// Volume mount points are often created 0755 by the runtime.
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, false, fmt.Errorf("secret: chmod dir: %w", err)
	}
	key = make([]byte, size)
	if _, err := rand.Read(key); err != nil {
		return nil, false, fmt.Errorf("secret: random: %w", err)
	}
	tmp, err := os.CreateTemp(dir, "."+name+".tmp-*")
	if err != nil {
		return nil, false, fmt.Errorf("secret: temp file: %w", err)
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return nil, false, fmt.Errorf("secret: chmod: %w", err)
	}
	if _, err := tmp.Write(key); err != nil {
		tmp.Close()
		return nil, false, fmt.Errorf("secret: write: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return nil, false, fmt.Errorf("secret: sync: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return nil, false, fmt.Errorf("secret: close: %w", err)
	}
	// Link never overwrites: the first publisher wins, the rest adopt its key.
	if err := os.Link(tmp.Name(), path); err != nil {
		if !os.IsExist(err) {
			return nil, false, fmt.Errorf("secret: publish: %w", err)
		}
		key, err = readKey(path, size)
		return key, false, err
	}
	if err := syncDir(dir); err != nil {
		return nil, false, fmt.Errorf("secret: sync dir: %w", err)
	}
	return key, true, nil
}

// readKey loads and validates an existing key file. The error wraps
// os.ErrNotExist when the file is absent and never contains key bytes.
func readKey(path string, size int) ([]byte, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, err
		}
		return nil, fmt.Errorf("secret: stat %s: %w", path, err)
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("secret: %s is not a regular file", path)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("secret: %s has mode %04o, want 0600", path, fi.Mode().Perm())
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("secret: read %s: %w", path, err)
	}
	if len(b) != size {
		return nil, fmt.Errorf("secret: %s has %d bytes, want %d; refusing to overwrite", path, len(b), size)
	}
	return b, nil
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
