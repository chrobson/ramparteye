package main

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/chrobson/ramparteye/internal/config"
	"github.com/chrobson/ramparteye/internal/db"
	"github.com/chrobson/ramparteye/internal/model"
	"github.com/chrobson/ramparteye/internal/runner"
	"github.com/chrobson/ramparteye/internal/scope"
	"github.com/chrobson/ramparteye/internal/store"
)

// cliProfileName is the profile `ramparteye scan <targets...>` creates or
// updates to cover exactly the given targets.
const cliProfileName = "CLI"

const scanUsage = "usage: ramparteye scan --profile NAME | ramparteye scan <target>..."

type scanArgs struct {
	profile string
	targets []string
}

func parseScanArgs(args []string) (scanArgs, error) {
	fs := flags("scan")
	var a scanArgs
	fs.StringVar(&a.profile, "profile", "", "scan profile name")
	if err := parseFlags(fs, args, scanUsage); err != nil {
		return a, err
	}
	if fs.NArg() > 0 {
		a.targets = fs.Args()
	}
	switch {
	case a.profile != "" && len(a.targets) > 0:
		return a, usageError("give either --profile or targets, not both\n" + scanUsage)
	case a.profile == "" && len(a.targets) == 0:
		return a, usageError(scanUsage)
	}
	return a, nil
}

func cmdScan(e *env, args []string) int {
	a, err := parseScanArgs(args)
	if err != nil {
		return e.fail("scan", err)
	}
	cfg, code := e.config()
	if code != exitOK {
		return code
	}
	ctx := e.ctx
	sc, err := requireScope(ctx, cfg)
	if err != nil {
		return e.fail("scan", err)
	}
	box, _, err := loadBox(&cfg, false)
	if err != nil {
		return e.fail("scan", err)
	}
	pool, st, err := openStore(ctx, cfg)
	if err != nil {
		return e.fail("scan", err)
	}
	defer pool.Close()
	if _, err := db.Migrate(ctx, pool); err != nil {
		return e.fail("scan", err)
	}
	log := e.logger()

	configID, err := scanProfile(ctx, e, st, a, sc, cfg)
	if err != nil {
		return e.fail("scan", err)
	}
	s := newScanner(cfg, st, sc, box, log, nil)
	// No Recover here: a running `serve` owns the chunks it leases.
	if err := s.runner.LoadSignatures(ctx); err != nil {
		return e.fail("scan", err)
	}

	events, unsubscribe := s.runner.Subscribe()
	defer unsubscribe()
	runID, err := s.runner.Start(ctx, configID)
	if err != nil {
		return e.fail("scan", err)
	}
	idle := make(chan struct{})
	go func() {
		s.runner.Wait()
		close(idle)
	}()
	followRun(events, idle, runID, e.stderr)
	shutdown(log, shutdownBudget, shutdownSteps{waitRuns: s.runner.Wait, closePusher: s.pusher.Close})

	// The summary is read even after Ctrl+C, which paused the run.
	rctx := context.WithoutCancel(ctx)
	run, err := st.Run(rctx, runID)
	if err != nil {
		return e.fail("scan", err)
	}
	var cr store.ChangeRun
	if run.Status == store.RunDone {
		if cr, err = st.ChangeRun(rctx, runID); err != nil {
			return e.fail("scan", err)
		}
	}
	printScanSummary(e.stdout, run, cr)
	if run.Status == store.RunPaused {
		fmt.Fprintf(e.stderr, "run %d paused; `ramparteye serve` resumes it\n", runID)
	}
	return scanExitCode(run.Status)
}

// scanProfile returns the profile to run: the named one, or the CLI
// profile updated to cover exactly the given targets.
func scanProfile(ctx context.Context, e *env, st *store.Store, a scanArgs, sc scope.Scope, cfg config.Config) (int64, error) {
	if a.profile == "" {
		res, err := ensureProfile(ctx, st, sc, nil, cliProfileName, a.targets, nil, defaultProfileRate(cfg))
		if err != nil {
			return 0, err
		}
		fmt.Fprintf(e.stderr, "profile %q covers %d targets (%d new)\n", res.Config, len(res.Targets), res.Imported)
		return res.ConfigID, nil
	}
	cs, err := st.ScanConfigs(ctx)
	if err != nil {
		return 0, err
	}
	var names []string
	for _, c := range cs {
		if c.Name == a.profile {
			return c.ID, nil
		}
		names = append(names, c.Name)
	}
	return 0, fmt.Errorf("no scan profile named %q (profiles: %s)", a.profile, strings.Join(names, ", "))
}

// followRun prints the progress of run runID from events until the run's
// session finishes or the runner has nothing left running, and returns
// the status of the finished event ("" when none arrived).
func followRun(events <-chan runner.Event, idle <-chan struct{}, runID int64, w io.Writer) string {
	lastPct := -1
	for {
		select {
		case ev, ok := <-events:
			if !ok {
				return ""
			}
			if ev.RunID != runID {
				continue
			}
			switch ev.Kind {
			case runner.EventStarted:
				fmt.Fprintf(w, "run %d started\n", runID)
			case runner.EventProgress:
				pct := int(ev.Progress * 100)
				if pct == lastPct {
					continue
				}
				lastPct = pct
				line := fmt.Sprintf("run %d: %d%% (%d pps)", runID, pct, ev.PPS)
				if ev.Message != "" {
					line += " " + ev.Message
				}
				fmt.Fprintln(w, line)
			case runner.EventFinished:
				fmt.Fprintf(w, "run %d finished: %s\n", runID, ev.Message)
				return ev.Message
			}
		case <-idle:
			return ""
		}
	}
}

// changeOrder is the order of change kinds in the summary.
var changeOrder = []model.ChangeKind{model.ChangeNew, model.ChangeGone, model.ChangeChanged,
	model.ChangeHostUp, model.ChangeHostDown, model.ChangeUnstable}

// printScanSummary prints the result counts of a run and, for a finished
// run, its changes against the previous run.
func printScanSummary(w io.Writer, run store.RunSummary, cr store.ChangeRun) {
	var b strings.Builder
	fmt.Fprintf(&b, "run %d %s", run.ID, run.Status)
	if run.DurationMS != nil {
		fmt.Fprintf(&b, " in %s", (time.Duration(*run.DurationMS) * time.Millisecond).Round(time.Second))
	}
	fmt.Fprintf(&b, ": %d hosts up, %d services", run.HostsUp, run.Services)
	if run.ChunksFailed > 0 {
		fmt.Fprintf(&b, ", %d of %d chunks failed", run.ChunksFailed, run.ChunksTotal)
	}
	b.WriteByte('\n')
	if run.Status == store.RunDone {
		switch {
		case cr.PrevRunID == 0:
			b.WriteString("first run: stored as the baseline for change detection\n")
		case cr.Total == 0:
			fmt.Fprintf(&b, "no changes since run %d\n", cr.PrevRunID)
		default:
			var parts []string
			for _, k := range changeOrder {
				if n := cr.Counts[k]; n > 0 {
					parts = append(parts, fmt.Sprintf("%d %s", n, strings.ReplaceAll(string(k), "_", " ")))
				}
			}
			fmt.Fprintf(&b, "changes since run %d: %s\n", cr.PrevRunID, strings.Join(parts, ", "))
		}
	}
	_, _ = io.WriteString(w, b.String())
}

// scanExitCode is 0 only for a run that finished successfully.
func scanExitCode(status string) int {
	if status == store.RunDone {
		return exitOK
	}
	return exitFail
}
