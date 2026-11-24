package exchange

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/chrobson/ramparteye/internal/diff"
	"github.com/chrobson/ramparteye/internal/model"
	"github.com/chrobson/ramparteye/internal/scope"
	"github.com/chrobson/ramparteye/internal/store"
)

// maxReportErrors bounds the messages kept in a Report.
const maxReportErrors = 100

// ErrNothingToImport is returned when no host of the file is left to import.
var ErrNothingToImport = errors.New("nothing to import")

// Report summarises an import.
type Report struct {
	RunID      int64    `json:"run_id"`
	Format     Format   `json:"format"`
	Hosts      int      `json:"hosts"`
	Services   int      `json:"services"`
	Detections int      `json:"detections"`
	Dropped    int      `json:"dropped"` // hosts outside the scope, not imported
	Errors     []string `json:"errors"`
}

func (r *Report) addError(msg string) {
	switch {
	case len(r.Errors) < maxReportErrors:
		r.Errors = append(r.Errors, msg)
	case len(r.Errors) == maxReportErrors:
		r.Errors = append(r.Errors, "further messages omitted")
	}
}

// Store writes obs as a new import run inside tx and returns its id.
// Hosts, services and detections outside s are dropped, counted in
// rep.Dropped and reported; an empty scope stores nothing and returns
// scope.ErrNoScope. The run is marked done but its diff is not applied:
// call store.ApplyRun after Store (Import does both in one transaction).
func Store(ctx context.Context, tx pgx.Tx, obs Observations, s scope.Scope, rep *Report) (int64, error) {
	if s.Empty() {
		return 0, scope.ErrNoScope
	}
	for _, e := range obs.Errors {
		rep.addError(e)
	}
	obs = filterScope(obs, s, rep)
	if len(obs.Hosts) == 0 {
		return 0, ErrNothingToImport
	}

	st := store.New(tx)
	runID, err := st.BeginImportRun(ctx)
	if err != nil {
		return 0, err
	}
	for _, h := range obs.Hosts {
		if err := st.ImportHost(ctx, runID, h); err != nil {
			return 0, fmt.Errorf("host %s: %w", h.IP, err)
		}
		rep.Hosts++
	}
	ids := map[model.AssetKey]int64{}
	for _, sv := range obs.Services {
		id, err := st.ImportService(ctx, runID, sv)
		if err != nil {
			return 0, fmt.Errorf("service %s:%d: %w", sv.Key.IP, sv.Key.Port, err)
		}
		if _, dup := ids[sv.Key]; !dup {
			rep.Services++
		}
		ids[sv.Key] = id
	}
	for _, d := range obs.Detections {
		id, ok := ids[d.Key]
		if !ok {
			continue
		}
		d.ServiceID = id
		if err := st.ImportDetection(ctx, d.Detection); err != nil {
			return 0, fmt.Errorf("detection %s: %w", d.SignatureID, err)
		}
		rep.Detections++
	}
	if err := st.FinishImportRun(ctx, runID); err != nil {
		return 0, err
	}
	rep.RunID = runID
	return runID, nil
}

// filterScope drops hosts, services and detections outside s.
func filterScope(obs Observations, s scope.Scope, rep *Report) Observations {
	out := Observations{}
	dropped := map[netip.Addr]bool{}
	ok := func(ip netip.Addr) bool {
		if s.Allows(ip) {
			return true
		}
		if !dropped[ip] {
			dropped[ip] = true
			rep.Dropped++
			rep.addError(fmt.Sprintf("host %s: outside the allowed scan scope, skipped", ip))
		}
		return false
	}
	for _, h := range obs.Hosts {
		if ok(h.IP) {
			out.Hosts = append(out.Hosts, h)
		}
	}
	for _, sv := range obs.Services {
		if ok(sv.Key.IP) {
			out.Services = append(out.Services, sv)
		}
	}
	for _, d := range obs.Detections {
		if ok(d.Key.IP) {
			out.Detections = append(out.Detections, d)
		}
	}
	return out
}

// Import parses b and stores it as one import run, then applies the run's
// diff the way the scan runner does (store.ApplyRun), all in one
// transaction: a failure leaves nothing behind.
func Import(ctx context.Context, db store.DBTX, b []byte, s scope.Scope, cfg diff.Config, now time.Time) (Report, error) {
	if s.Empty() {
		return Report{}, scope.ErrNoScope
	}
	format, obs, err := Parse(b)
	if err != nil {
		return Report{Format: format}, err
	}
	rep := Report{Format: format}
	err = pgx.BeginFunc(ctx, db, func(tx pgx.Tx) error {
		id, err := Store(ctx, tx, obs, s, &rep)
		if err != nil {
			return err
		}
		if _, err := store.New(tx).ApplyRun(ctx, id, cfg, now); err != nil {
			return fmt.Errorf("apply diff: %w", err)
		}
		return nil
	})
	if err != nil {
		return Report{Format: format, Dropped: rep.Dropped, Errors: rep.Errors}, err
	}
	return rep, nil
}
