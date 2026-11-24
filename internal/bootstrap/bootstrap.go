// Package bootstrap seeds the first administrator on first start.
package bootstrap

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"math/big"
	"strings"

	"github.com/chrobson/ramparteye/internal/auth"
	"github.com/chrobson/ramparteye/internal/config"
	"github.com/chrobson/ramparteye/internal/model"
)

// Store is the persistence Ensure needs; the Postgres store satisfies it.
type Store interface {
	CountUsers(ctx context.Context) (int, error)
	// CreateInitialUsers creates all users or none, and only while no user
	// exists; it reports whether it created them.
	CreateInitialUsers(ctx context.Context, users []model.NewUser) (bool, error)
}

// Result reports what Ensure did.
type Result struct {
	AdminCreated bool
	DemoAccounts bool
}

const (
	alphabet       = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789-_"
	passwordLength = 24
)

type account struct{ login, role string }

var demoAccounts = []account{
	{"admin", "Admin"}, {"operator", "Operator"}, {"analyst", "Analyst"}, {"viewer", "Viewer"},
}

// Ensure creates the initial accounts when the user table is empty. A
// generated password is written to out only after every account has been
// stored, and never again: a restart with existing users does nothing and
// prints nothing.
func Ensure(ctx context.Context, st Store, cfg config.Config, out io.Writer) (Result, error) {
	return ensure(ctx, st, cfg, out, auth.HashPassword)
}

func ensure(ctx context.Context, st Store, cfg config.Config, out io.Writer, hash func(string) (string, error)) (Result, error) {
	n, err := st.CountUsers(ctx)
	if err != nil {
		return Result{}, fmt.Errorf("bootstrap: count users: %w", err)
	}
	if n > 0 {
		return Result{}, nil
	}

	accounts := []account{{"admin", "Admin"}}
	if cfg.Demo {
		accounts = demoAccounts
	}
	passwords := make([]string, len(accounts))
	users := make([]model.NewUser, len(accounts))
	for i, a := range accounts {
		pw, err := generatePassword()
		if err != nil {
			return Result{}, err
		}
		h, err := hash(pw)
		if err != nil {
			return Result{}, fmt.Errorf("bootstrap: hash password: %w", err)
		}
		passwords[i] = pw
		// Demo accounts are throwaway; the real admin must rotate on login.
		users[i] = model.NewUser{Login: a.login, PasswordHash: h, Role: a.role, MustChangePassword: !cfg.Demo}
	}
	created, err := st.CreateInitialUsers(ctx, users)
	if err != nil {
		return Result{}, fmt.Errorf("bootstrap: create users: %w", err)
	}
	if !created { // another process won the first start and printed its passwords
		return Result{}, nil
	}

	var b strings.Builder
	if cfg.Demo {
		b.WriteString("demo accounts (passwords shown once):\n")
		fmt.Fprintf(&b, "  %-10s %-10s %s\n", "LOGIN", "ROLE", "PASSWORD")
		for i, a := range accounts {
			fmt.Fprintf(&b, "  %-10s %-10s %s\n", a.login, a.role, passwords[i])
		}
	} else {
		fmt.Fprintf(&b, "admin password (shown once): %s\n", passwords[0])
	}
	if _, err := io.WriteString(out, b.String()); err != nil {
		return Result{}, fmt.Errorf("bootstrap: print credentials: %w", err)
	}
	return Result{AdminCreated: true, DemoAccounts: cfg.Demo}, nil
}

func generatePassword() (string, error) {
	max := big.NewInt(int64(len(alphabet)))
	b := make([]byte, passwordLength)
	for i := range b {
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", fmt.Errorf("bootstrap: random: %w", err)
		}
		b[i] = alphabet[n.Int64()]
	}
	return string(b), nil
}
