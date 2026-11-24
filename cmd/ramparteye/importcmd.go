package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/chrobson/ramparteye/internal/diff"
	"github.com/chrobson/ramparteye/internal/exchange"
)

// cmdImport imports nmap XML or Generic Findings JSON as a run of kind
// "import", exactly like the web upload: hosts outside the scope are
// dropped and the run's diff is applied in the same transaction.
func cmdImport(e *env, args []string) int {
	if len(args) != 1 {
		return e.fail("import", usageError("usage: ramparteye import <file>"))
	}
	cfg, code := e.config()
	if code != exitOK {
		return code
	}
	ctx := e.ctx
	sc, err := requireScope(ctx, cfg)
	if err != nil {
		return e.fail("import", err)
	}
	b, err := readImport(args[0])
	if err != nil {
		return e.fail("import", err)
	}
	x, closeX, err := e.exchange(ctx, cfg)
	if err != nil {
		return e.fail("import", err)
	}
	defer closeX()
	rep, ierr := x.Import(ctx, b, sc, diff.Config(cfg.Unstable), time.Now())
	enc := json.NewEncoder(e.stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(rep); err != nil {
		return e.fail("import", err)
	}
	if ierr != nil {
		return e.fail("import", ierr)
	}
	return exitOK
}

// readImport reads at most exchange.MaxImportSize bytes of path.
func readImport(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, exchange.MaxImportSize+1))
	if err != nil {
		return nil, err
	}
	if len(b) > exchange.MaxImportSize {
		return nil, fmt.Errorf("%s: file too large (at most %d MiB)", path, exchange.MaxImportSize>>20)
	}
	return b, nil
}
