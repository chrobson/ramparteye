package main

import (
	"fmt"
	"strings"

	"github.com/chrobson/ramparteye/internal/db"
)

func cmdMigrate(e *env, args []string) int {
	if len(args) > 0 {
		return e.fail("migrate", usageError("usage: ramparteye migrate"))
	}
	cfg, code := e.config()
	if code != exitOK {
		return code
	}
	pool, _, err := openStore(e.ctx, cfg)
	if err != nil {
		return e.fail("migrate", err)
	}
	defer pool.Close()
	applied, err := db.Migrate(e.ctx, pool)
	if err != nil {
		return e.fail("migrate", err)
	}
	if len(applied) == 0 {
		fmt.Fprintln(e.stdout, "database schema is up to date")
		return exitOK
	}
	fmt.Fprintf(e.stdout, "applied migrations: %s\n", strings.Join(applied, ", "))
	return exitOK
}
