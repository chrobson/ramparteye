package main

import (
	"encoding/json"
	"fmt"

	"github.com/chrobson/ramparteye/internal/dojo"
)

const dojoUsage = "usage: ramparteye dojo push [--run ID]"

// cmdDojo pushes a finished run (default: the latest) to DefectDojo now.
// The attempt is recorded in the push history with trigger "cli".
func cmdDojo(e *env, args []string) int {
	if len(args) == 0 || args[0] != "push" {
		return e.fail("dojo", usageError(dojoUsage))
	}
	fs := flags("dojo push")
	var runID runIDFlag
	fs.Var(&runID, "run", "run id (default: the latest finished run)")
	if err := parseFlags(fs, args[1:], dojoUsage); err != nil {
		return e.fail("dojo", err)
	}
	if fs.NArg() > 0 {
		return e.fail("dojo", usageError(dojoUsage))
	}
	cfg, code := e.config()
	if code != exitOK {
		return code
	}
	box, _, err := loadBox(&cfg)
	if err != nil {
		return e.fail("dojo", err)
	}
	pool, st, err := openStore(e.ctx, cfg)
	if err != nil {
		return e.fail("dojo", err)
	}
	defer pool.Close()
	p := dojo.NewPusher(st, dojo.StoredSettings(st, box, cfg), dojo.DefaultClient)
	p.Log = e.logger()
	rec, perr := p.PushRun(e.ctx, int64(runID), dojo.TriggerCLI)
	if perr == nil || rec.RunID != 0 {
		out, err := json.MarshalIndent(rec, "", "  ")
		if err != nil {
			return e.fail("dojo", err)
		}
		fmt.Fprintln(e.stdout, string(out))
	}
	if perr != nil {
		return e.fail("dojo", perr)
	}
	return exitOK
}
