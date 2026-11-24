package main

import (
	"context"
	"errors"
	"fmt"

	"github.com/chrobson/ramparteye/internal/auth"
	"github.com/chrobson/ramparteye/internal/bootstrap"
	"github.com/chrobson/ramparteye/internal/store"
)

const resetAdminUsage = "usage: ramparteye reset-admin [--login NAME]"

// auditPasswordReset is the audit action of reset-admin.
const auditPasswordReset = "user.password.reset"

// lockoutNote tells the operator that reset-admin cannot clear the login
// throttle, which only the serve process holds.
const lockoutNote = "Login lockout (if any) clears within 15 minutes or on restart of serve."

// cmdResetAdmin sets a new random password for a user (default admin) that
// must be changed at the next login, re-enables the account, ends its
// sessions and prints the password once. It is the recovery path for a lost
// admin password or a first start whose password was never shown.
func cmdResetAdmin(e *env, args []string) int {
	fs := flags("reset-admin")
	login := fs.String("login", "admin", "login of the user")
	if err := parseFlags(fs, args, resetAdminUsage); err != nil {
		return e.fail("reset-admin", err)
	}
	if fs.NArg() > 0 || *login == "" {
		return e.fail("reset-admin", usageError(resetAdminUsage))
	}
	cfg, code := e.config()
	if code != exitOK {
		return code
	}
	pool, st, err := openStore(e.ctx, cfg)
	if err != nil {
		return e.fail("reset-admin", err)
	}
	defer pool.Close()
	pw, err := resetPassword(e.ctx, st, *login)
	if err != nil {
		return e.fail("reset-admin", err)
	}
	fmt.Fprintf(e.stdout, "new password for %s (shown once, must be changed at login): %s\n", *login, pw)
	// The login throttle lives in the memory of the serve process.
	fmt.Fprintln(e.stdout, lockoutNote)
	return exitOK
}

// resetPassword does the reset in one transaction and returns the password.
func resetPassword(ctx context.Context, st *store.Store, login string) (string, error) {
	pw, err := bootstrap.GeneratePassword()
	if err != nil {
		return "", err
	}
	hash, err := auth.HashPassword(pw)
	if err != nil {
		return "", err
	}
	err = st.InTx(ctx, func(tx *store.Store) error {
		u, err := tx.UserByLogin(ctx, login)
		if errors.Is(err, store.ErrNotFound) {
			return fmt.Errorf("no user with login %q", login)
		}
		if err != nil {
			return err
		}
		if err := tx.SetPassword(ctx, u.ID, hash, true); err != nil {
			return err
		}
		if u.Disabled {
			if err := tx.SetUserDisabled(ctx, u.ID, false); err != nil {
				return err
			}
		}
		if err := tx.DeleteUserSessions(ctx, u.ID); err != nil {
			return err
		}
		return tx.InsertAudit(ctx, nil, auditPasswordReset, "user:"+u.Login,
			map[string]any{"actor": "cli", "reenabled": u.Disabled})
	})
	if err != nil {
		return "", err
	}
	return pw, nil
}
