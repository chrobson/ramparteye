package runner

import (
	"context"
	"fmt"
	"time"

	"github.com/chrobson/ramparteye/internal/sig"
	"github.com/chrobson/ramparteye/internal/store"
)

// Due reports whether a periodic profile should start a new run at now given
// its last run (nil = never ran). Profiles without every_minutes are manual.
func Due(now time.Time, cfg store.ScanConfig, last *store.RunInfo) bool {
	if cfg.EveryMinutes == nil || *cfg.EveryMinutes <= 0 {
		return false
	}
	if last == nil || last.StartedAt == nil {
		return true
	}
	return !now.Before(last.StartedAt.Add(time.Duration(*cfg.EveryMinutes) * time.Minute))
}

// Recover must be called once at startup, before the first Tick. Chunks left
// running by a previous process return to pending and their runs become
// paused (store.ResetRunning: one scanning process per database). It also
// syncs the built-in signatures into the store and loads the enabled ones
// into the engine.
func (r *Runner) Recover(ctx context.Context) error {
	n, err := r.st.ResetRunning(ctx)
	if err != nil {
		return fmt.Errorf("reset running chunks: %w", err)
	}
	if n > 0 {
		r.cfg.Log.Info("scan chunks reset to pending", "count", n)
	}
	if r.eng == nil {
		return nil
	}
	if err := sig.SyncBuiltin(ctx, r.st, r.cfg.Log); err != nil {
		return fmt.Errorf("sync built-in signatures: %w", err)
	}
	sigs, err := sig.LoadEnabled(ctx, r.st)
	if err != nil {
		r.cfg.Log.Warn("some signatures not loaded", "err", err)
	}
	if sigs != nil || err == nil {
		r.eng.SetSignatures(sigs)
	}
	return nil
}

// Loop calls Recover and then Tick every interval until ctx is done, then
// waits for the running scans to stop (they are paused, not lost).
func (r *Runner) Loop(ctx context.Context, every time.Duration) error {
	if every <= 0 {
		every = time.Minute
	}
	if err := r.Recover(ctx); err != nil {
		return err
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		r.Tick(ctx, r.cfg.Now())
		select {
		case <-ctx.Done():
			r.Wait()
			return nil
		case <-t.C:
		}
	}
}

// Tick is one scheduler step at now. It first stores the status of the
// runs whose FinishRun failed (stale), whatever their profile. Then for
// every profile it:
//   - pauses a scheduled run executing here when now is outside the window
//     or the profile was disabled (manual runs ignore the window);
//   - resumes the oldest queued or paused run of the profile inside the
//     window;
//   - starts a new run when the profile is due and inside the window.
//
// Runs execute in goroutines bound to ctx, which must live as long as the
// process; a scheduled run's context ends at its window end, so it pauses
// by itself and its interrupted chunks return to pending. Errors are logged.
func (r *Runner) Tick(ctx context.Context, now time.Time) {
	r.retryStale(ctx)
	cfgs, err := r.st.ScanConfigs(ctx)
	if err != nil {
		r.cfg.Log.Error("scheduler: load scan profiles", "err", err)
		return
	}
	open, err := r.st.OpenRuns(ctx)
	if err != nil {
		r.cfg.Log.Error("scheduler: load open runs", "err", err)
		return
	}
	openByCfg := map[int64]store.RunInfo{}
	elsewhere := map[int64]bool{}
	for _, o := range open {
		if o.ConfigID == nil {
			continue
		}
		// A run whose status this process still fails to store (stale) is
		// left alone: retryStale stores it, it is never executed again.
		if r.isStale(o.ID) {
			continue
		}
		// A running run not executing here belongs to another live process
		// (runs of a dead process were reset to paused by Recover).
		if o.Status == store.RunRunning {
			if !r.isActive(o.ID) {
				elsewhere[*o.ConfigID] = true
			}
			continue
		}
		if _, ok := openByCfg[*o.ConfigID]; !ok { // oldest open run first
			openByCfg[*o.ConfigID] = o
		}
	}
	for _, cfg := range cfgs {
		if elsewhere[cfg.ID] {
			continue
		}
		if err := r.tickConfig(ctx, now, cfg, openByCfg); err != nil {
			r.cfg.Log.Error("scheduler", "profile", cfg.Name, "err", err)
		}
	}
}

func (r *Runner) tickConfig(ctx context.Context, now time.Time, cfg store.ScanConfig, open map[int64]store.RunInfo) error {
	inWin, deadline := true, time.Time{}
	if cfg.HasWindow() {
		from, to := NextWindow(now, *cfg.WindowStart, *cfg.WindowEnd)
		inWin = !now.Before(from) && now.Before(to)
		deadline = to
	}
	r.mu.Lock()
	a, starting := r.activeLocked(cfg.ID), r.starting[cfg.ID]
	if a != nil && !a.manual && (!inWin || !cfg.Enabled) {
		a.ctl.stop() // the run saves itself as paused
	}
	r.mu.Unlock()
	if a != nil || starting || !cfg.Enabled || !inWin {
		return nil
	}
	if o, ok := open[cfg.ID]; ok {
		if !r.reserve(cfg.ID) {
			return nil
		}
		defer r.release(cfg.ID)
		r.cfg.Log.Info("resuming scan run", "run", o.ID, "profile", cfg.Name, "until", deadline)
		r.launch(ctx, o.ID, cfg, deadline, now, false)
		return nil
	}
	if !Due(now, cfg, nil) {
		return nil
	}
	last, err := r.st.LastRun(ctx, cfg.ID)
	if err != nil {
		return err
	}
	if !Due(now, cfg, last) {
		return nil
	}
	if !r.reserve(cfg.ID) {
		return nil
	}
	defer r.release(cfg.ID)
	runID, err := r.createRun(ctx, cfg)
	if err != nil {
		return err
	}
	r.cfg.Log.Info("scheduled scan run", "run", runID, "profile", cfg.Name, "until", deadline)
	r.launch(ctx, runID, cfg, deadline, now, false)
	return nil
}
