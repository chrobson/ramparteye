// Package auth implements passwords, sessions, RBAC, login throttling and
// CSRF protection. It is a library plus HTTP middleware; pages live in web.
package auth

import (
	"errors"
	"sync"

	"golang.org/x/crypto/bcrypt"
)

const (
	// MinPasswordLen is the minimum accepted password length.
	MinPasswordLen = 8
	// MaxPasswordLen is the bcrypt input limit in bytes.
	MaxPasswordLen = 72
)

var (
	// ErrWeakPassword is returned for passwords shorter than MinPasswordLen.
	ErrWeakPassword = errors.New("password shorter than 8 bytes")
	// ErrLongPassword is returned for passwords longer than MaxPasswordLen
	// bytes.
	ErrLongPassword = errors.New("password longer than 72 bytes")
)

// bcryptCost is a variable so tests can lower it.
var bcryptCost = bcrypt.DefaultCost

// HashPassword returns a bcrypt hash of pw.
func HashPassword(pw string) (string, error) {
	if len(pw) < MinPasswordLen {
		return "", ErrWeakPassword
	}
	if len(pw) > MaxPasswordLen {
		return "", ErrLongPassword
	}
	h, err := bcrypt.GenerateFromPassword([]byte(pw), bcryptCost)
	return string(h), err
}

// CheckPassword reports whether pw matches the bcrypt hash.
func CheckPassword(hash, pw string) bool {
	if len(pw) > MaxPasswordLen {
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(pw)) == nil
}

// dummyHash is compared against when a login does not exist, so response
// time does not reveal which logins are valid. It is built lazily at the
// current bcrypt cost.
var dummyHash = sync.OnceValue(func() string {
	h, _ := bcrypt.GenerateFromPassword([]byte("rampart-dummy-password"), bcryptCost)
	return string(h)
})
