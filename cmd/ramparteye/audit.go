package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/chrobson/ramparteye/internal/safety"
	"github.com/chrobson/ramparteye/internal/store"
)

// auditLookback is how many recent runs `audit` searches for a receipt.
const auditLookback = 100

// cmdAudit prints the safety report of a run (default: the newest run with
// a receipt), the same JSON as GET /scans/{id}/safety.json. It exits
// non-zero unless every check passed.
func cmdAudit(e *env, args []string) int {
	var runID int64
	switch len(args) {
	case 0:
	case 1:
		id, err := parseRunID(args[0])
		if err != nil {
			return e.fail("audit", err)
		}
		runID = id
	default:
		return e.fail("audit", usageError("usage: ramparteye audit [run]"))
	}
	cfg, code := e.config()
	if code != exitOK {
		return code
	}
	pool, st, err := openStore(e.ctx, cfg)
	if err != nil {
		return e.fail("audit", err)
	}
	defer pool.Close()
	rc, err := loadReceipt(e.ctx, st, runID)
	if err != nil {
		return e.fail("audit", err)
	}
	rep := safety.BuildReport(rc)
	out, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return e.fail("audit", err)
	}
	fmt.Fprintln(e.stdout, string(out))
	if !rep.OK {
		fmt.Fprintf(e.stderr, "ramparteye: audit: run %d: safety report %s\n", rc.RunID, rep.Status)
		return exitFail
	}
	return exitOK
}

// loadReceipt loads the receipt of runID, or of the newest run that has one.
func loadReceipt(ctx context.Context, st *store.Store, runID int64) (safety.Receipt, error) {
	if runID != 0 {
		return st.SafetyReceipt(ctx, runID)
	}
	runs, err := st.Runs(ctx, auditLookback)
	if err != nil {
		return safety.Receipt{}, err
	}
	for _, r := range runs {
		rc, err := st.SafetyReceipt(ctx, r.ID)
		if errors.Is(err, safety.ErrNoReceipt) {
			continue
		}
		return rc, err
	}
	return safety.Receipt{}, safety.ErrNoReceipt
}
