package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/chrobson/ramparteye/internal/diff"
	"github.com/chrobson/ramparteye/internal/model"
)

// ErrAlreadyApplied is returned by ApplyRun for a run applied before.
var ErrAlreadyApplied = errors.New("diff already applied for this run")

// ApplyResult describes what ApplyRun did.
type ApplyResult struct {
	RunID     int64
	PrevRunID int64 // 0 = baseline run, no changes recorded
	Changes   []model.Change
	Hosts     []model.HostState // states of the hosts in the run's scope after the run
}

// ApplyRun compares run runID with the previous finished scan run, stores
// the changes and advances host_state, all in one transaction serialised by
// LockDiff. Imports are never a baseline, and an import is compared only on
// the hosts it contains. Call it once the run's host_obs, services and HTTP
// observations are stored. The first run ever is a baseline: host states are
// created but no changes are recorded. A second call for the same run
// returns ErrAlreadyApplied.
func (s *Store) ApplyRun(ctx context.Context, runID int64, cfg diff.Config, now time.Time) (ApplyResult, error) {
	var res ApplyResult
	err := s.InTx(ctx, func(tx *Store) error {
		var err error
		res, err = tx.applyRun(ctx, runID, cfg, now)
		return err
	})
	return res, err
}

func (s *Store) applyRun(ctx context.Context, runID int64, cfg diff.Config, now time.Time) (ApplyResult, error) {
	res := ApplyResult{RunID: runID}
	if err := s.LockDiff(ctx); err != nil {
		return res, err
	}
	applied, err := s.DiffApplied(ctx, runID)
	if err != nil {
		return res, err
	}
	if applied {
		return res, ErrAlreadyApplied
	}
	if res.PrevRunID, err = s.PrevScanRunID(ctx, runID); err != nil {
		return res, fmt.Errorf("previous run: %w", err)
	}
	curr, err := s.RunServices(ctx, runID)
	if err != nil {
		return res, fmt.Errorf("current services: %w", err)
	}
	var prev []model.ServiceObs
	if res.PrevRunID != 0 {
		if prev, err = s.RunServicesInScope(ctx, res.PrevRunID, runID); err != nil {
			return res, fmt.Errorf("previous services: %w", err)
		}
	}
	obs, err := s.RunHostObs(ctx, runID)
	if err != nil {
		return res, fmt.Errorf("host observations: %w", err)
	}
	known, err := s.HostStatesInScope(ctx, runID)
	if err != nil {
		return res, fmt.Errorf("host states: %w", err)
	}
	isImport, err := s.RunIsImport(ctx, runID)
	if err != nil {
		return res, err
	}

	res.Hosts = diff.AdvanceAt(known, obs, curr, runID, now, cfg)
	if res.PrevRunID != 0 {
		if res.Changes, err = s.runChanges(ctx, runID, res.PrevRunID, prev, curr, res.Hosts, isImport, cfg); err != nil {
			return res, err
		}
	}
	if err := s.SaveHostStates(ctx, res.Hosts); err != nil {
		return res, fmt.Errorf("host states: %w", err)
	}
	if err := s.InsertChanges(ctx, res.Changes); err != nil {
		return res, fmt.Errorf("insert changes: %w", err)
	}
	if err := s.MarkDiffApplied(ctx, runID, res.PrevRunID, len(res.Changes)); err != nil {
		return res, err
	}
	return res, nil
}

// runChanges computes the changes of runID against prevRunID.
func (s *Store) runChanges(ctx context.Context, runID, prevRunID int64, prev, curr []model.ServiceObs,
	hosts []model.HostState, isImport bool, cfg diff.Config) ([]model.Change, error) {
	cs := diff.Diff(prev, curr, hosts, cfg)
	if isImport {
		// An import file carries only some fields; a missing one is
		// unknown, not removed. Imports carry no HTTP timing either.
		cs = diff.DropUncarried(cs)
	} else {
		lat, err := s.RunLatencies(ctx, runID, prevRunID)
		if err != nil {
			return nil, fmt.Errorf("response times: %w", err)
		}
		cs = append(cs, diff.LatencyChanges(prev, curr, lat)...)
		// A reverse proxy answering 502/503/504 for a dead upstream is
		// fingerprinted as the proxy: one http_status row, not five.
		st, err := s.RunHTTPStatus(ctx, runID, prevRunID)
		if err != nil {
			return nil, fmt.Errorf("http status: %w", err)
		}
		cs = diff.CollapseGateway(prev, curr, st, cs)
		// A service that keeps disappearing and coming back is unstable.
		var keys []model.AssetKey
		for _, c := range cs {
			if c.Kind == model.ChangeNew || c.Kind == model.ChangeGone {
				keys = append(keys, c.Key)
			}
		}
		prior, err := s.ServiceFlips(ctx, runID, keys, diff.PriorRuns(cfg))
		if err != nil {
			return nil, fmt.Errorf("service flips: %w", err)
		}
		cs = append(cs, diff.ServiceInstability(cs, prior, cfg)...)
		diff.SortChanges(cs)
	}
	for i := range cs {
		cs[i].RunID, cs[i].PrevRunID = runID, prevRunID
	}
	return cs, nil
}
