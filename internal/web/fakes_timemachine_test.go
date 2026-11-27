package web

import (
	"context"
	"sort"

	"github.com/chrobson/ramparteye/internal/model"
	"github.com/chrobson/ramparteye/internal/store"
)

// runFixture is what the fake store returns for the queries of one run.
type runFixture struct {
	changes  []model.Change
	hostObs  []model.HostObs
	services []store.ExportService
}

// fakeRuns returns every run of the fixtures, newest first.
func (f *fakeStore) fakeRuns() []store.RunSummary {
	seen := map[int64]bool{}
	var out []store.RunSummary
	for _, r := range append(append([]store.RunSummary{}, f.dash.runs...), f.dash.allRuns...) {
		if !seen[r.ID] {
			seen[r.ID] = true
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID > out[j].ID })
	return out
}

func (f *fakeStore) DoneRuns(_ context.Context, limit int) ([]store.RunSummary, error) {
	var out []store.RunSummary
	for _, r := range f.fakeRuns() {
		if r.Status == store.RunDone && len(out) < limit {
			out = append(out, r)
		}
	}
	return out, nil
}

func (f *fakeStore) AdjacentDoneRuns(_ context.Context, runID int64) (prev, next int64, err error) {
	for _, r := range f.fakeRuns() {
		switch {
		case r.Status != store.RunDone:
		case r.ID < runID && prev == 0:
			prev = r.ID
		case r.ID > runID:
			next = r.ID
		}
	}
	return prev, next, nil
}
