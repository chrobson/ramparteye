package main

import (
	"errors"
	"fmt"

	"github.com/chrobson/ramparteye/internal/exchange"
	"github.com/chrobson/ramparteye/internal/store"
)

const exportUsage = "usage: ramparteye export [--format csv|json|dojo] [--run ID]"

// cmdExport writes a finished run (default: the latest) to stdout as CSV,
// JSON or DefectDojo Generic Findings JSON.
func cmdExport(e *env, args []string) int {
	fs := flags("export")
	format := fs.String("format", "csv", "csv, json or dojo")
	var runID runIDFlag
	fs.Var(&runID, "run", "run id (default: the latest finished run)")
	if err := parseFlags(fs, args, exportUsage); err != nil {
		return e.fail("export", err)
	}
	if fs.NArg() > 0 {
		return e.fail("export", usageError(exportUsage))
	}
	write, ok := exportWriters[*format]
	if !ok {
		return e.fail("export", usageError(fmt.Sprintf("unknown export format %q (csv, json or dojo)\n%s", *format, exportUsage)))
	}
	cfg, code := e.config()
	if code != exitOK {
		return code
	}
	x, closeX, err := e.exchange(e.ctx, cfg)
	if err != nil {
		return e.fail("export", err)
	}
	defer closeX()
	snap, err := x.Snapshot(e.ctx, int64(runID))
	if errors.Is(err, store.ErrNotFound) {
		if runID == 0 {
			return e.fail("export", errors.New("no finished run to export"))
		}
		return e.fail("export", fmt.Errorf("run %d not found or not finished", runID))
	}
	if err != nil {
		return e.fail("export", err)
	}
	if err := write(e, snap); err != nil {
		return e.fail("export", err)
	}
	return exitOK
}

var exportWriters = map[string]func(e *env, s exchange.Snapshot) error{
	"csv":  func(e *env, s exchange.Snapshot) error { return exchange.WriteCSV(e.stdout, s) },
	"json": func(e *env, s exchange.Snapshot) error { return exchange.WriteJSON(e.stdout, s) },
	"dojo": func(e *env, s exchange.Snapshot) error {
		b, err := s.Dojo()
		if err != nil {
			return err
		}
		_, err = e.stdout.Write(append(b, '\n'))
		return err
	},
}
