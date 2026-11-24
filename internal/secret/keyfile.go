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
// touches nothing on disk. An existing file of the wrong size is an error and
// is never overwritten, so a restart can never silently rotate a key.
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
	if name == "" || name != filepath.Base(name) || name == "." || name == ".." {
		return nil, false, fmt.Errorf("secret: invalid key file name %q", name)
	}
	path := filepath.Join(dir, name)

	if b, rerr := os.ReadFile(path); rerr == nil {
		if len(b) != size {
			return nil, false, fmt.Errorf("secret: %s has %d bytes, want %d; refusing to overwrite", path, len(b), size)
		}
		return b, false, nil
	} else if !os.IsNotExist(rerr) {
		return nil, false, fmt.Errorf("secret: read %s: %w", path, rerr)
	}

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, false, fmt.Errorf("secret: create dir: %w", err)
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
	if err := os.Rename(tmp.Name(), path); err != nil {
		return nil, false, fmt.Errorf("secret: publish: %w", err)
	}
	return key, true, nil
}
