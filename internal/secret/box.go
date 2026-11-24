// Package secret provides authenticated encryption for values stored at rest
// and management of the key files that protect them.
package secret

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
)

// KeySize is the required key length in bytes (AES-256).
const KeySize = 32

// Box seals and opens values with AES-256-GCM.
type Box struct {
	aead cipher.AEAD
}

// NewBox returns a Box for a 32-byte key.
func NewBox(key []byte) (*Box, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("secret: key must be %d bytes, got %d", KeySize, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("secret: cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("secret: gcm: %w", err)
	}
	return &Box{aead: aead}, nil
}

// Seal encrypts plain, binding it to aad. The random nonce is prepended to
// the returned ciphertext.
func (b *Box) Seal(plain []byte, aad string) ([]byte, error) {
	nonce := make([]byte, b.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("secret: nonce: %w", err)
	}
	return b.aead.Seal(nonce, nonce, plain, []byte(aad)), nil
}

// Open decrypts ct produced by Seal. It fails when aad differs or the
// ciphertext was modified.
func (b *Box) Open(ct []byte, aad string) ([]byte, error) {
	n := b.aead.NonceSize()
	if len(ct) < n+b.aead.Overhead() {
		return nil, errors.New("secret: ciphertext too short")
	}
	plain, err := b.aead.Open(nil, ct[:n], ct[n:], []byte(aad))
	if err != nil {
		return nil, errors.New("secret: decryption failed")
	}
	return plain, nil
}
