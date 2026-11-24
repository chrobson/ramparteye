// Package bootstrap seeds the first administrator on first start.
package bootstrap

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"math/big"
	"strings"

	"golang.org/x/crypto/bcrypt"

	"github.com/chrobson/ramparteye/internal/config"
)

// Store is the persistence Ensure needs; the Postgres store satisfies it.
type Store interface {
	CountUsers(ctx context.Context) (int, error)
	CreateUser(ctx context.Context, login, passwordHash, role string, mustChangePassword bool) error
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
	return ensure(ctx, st, cfg, out, bcryptHash)
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
	for i, a := range accounts {
		pw, err := generatePassword()
		if err != nil {
			return Result{}, err
		}
		h, err := hash(pw)
		if err != nil {
			return Result{}, fmt.Errorf("bootstrap: hash password: %w", err)
		}
		// Demo accounts are throwaway; the real admin must rotate on login.
		if err := st.CreateUser(ctx, a.login, h, a.role, !cfg.Demo); err != nil {
			return Result{}, fmt.Errorf("bootstrap: create %s: %w", a.login, err)
		}
		passwords[i] = pw
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

func bcryptHash(pw string) (string, error) {
	h, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	return string(h), err
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
