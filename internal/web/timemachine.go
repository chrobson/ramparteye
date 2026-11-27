package web

// The time machine: the asset pages as of one finished run (?run=N).
//
// Observations (hosts, services, HTTP probes, detections) and changes are
// stored per run, so a past view shows them as run N saw them, scored with
// run N's own changes. Host state (up, down, inactive, unstable) is stored
// only as the current state, so a past view shows only whether run N itself
// got an answer from a host. Annotations are current: they are shown, and
// count in the score as they do today, but are edited only in the latest
// view.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"time"

	"github.com/chrobson/ramparteye/internal/auth"
	"github.com/chrobson/ramparteye/internal/model"
	"github.com/chrobson/ramparteye/internal/store"
)

// pickerRuns is the number of finished runs offered by the run picker.
const pickerRuns = 50

// AsOf is the time machine banner of a page showing finished run RunID.
type AsOf struct {
	RunID      int64
	Profile    string
	Import     bool
	FinishedAt time.Time
	When       string // finish time, UTC
	Compared   bool   // the run was compared with an earlier one (or is the baseline)
	BaseRunID  int64  // the run it was compared with; 0 = baseline
	Narrow     string // why the run saw less than the whole inventory ("" = it did not)
	OlderID    int64  // the finished run before (0 = none)
	NewerID    int64  // the finished run after (0 = none)
	OlderHref  string
	NewerHref  string
	LatestHref string
	CanExport  bool
}

// run is the run shown, 0 (the latest view) for nil.
func (a *AsOf) run() int64 {
	if a == nil {
		return 0
	}
	return a.RunID
}

// titleSuffix is appended to the page title: "" for the latest view.
func (a *AsOf) titleSuffix() string {
	if a == nil {
		return ""
	}
	return " as of run #" + strconv.FormatInt(a.RunID, 10)
}

// snapshotAsOf loads the snapshot of the latest view (asOf nil) or of the
// run asOf shows.
func (s *Server) snapshotAsOf(ctx context.Context, asOf *AsOf) (snapshot, error) {
	if asOf == nil {
		return s.loadSnapshot(ctx)
	}
	return s.loadSnapshotAt(ctx, asOf.RunID)
}

// RunOption is a finished run in the run picker.
type RunOption struct {
	ID       int64
	Label    string
	Selected bool
}

// runError is a run parameter the time machine refuses, with its page.
type runError struct {
	code        int
	title, text string
}

func (e *runError) Error() string { return e.text }

var errBadRunParam = &runError{code: http.StatusBadRequest, title: "Invalid run",
	text: "The run parameter must be the number of a finished run. Pick a run from the list on the Assets page."}

// parseRunParam reads ?run=: 0 when it is absent or empty, errBadRunParam
// unless it is a positive decimal integer.
func parseRunParam(q url.Values) (int64, error) {
	v := q.Get("run")
	if v == "" {
		return 0, nil
	}
	for _, c := range v {
		if c < '0' || c > '9' {
			return 0, errBadRunParam
		}
	}
	id, err := strconv.ParseInt(v, 10, 64)
	if err != nil || id <= 0 {
		return 0, errBadRunParam
	}
	return id, nil
}

// finishedRun loads run id and refuses it (*runError) unless it is done.
func (s *Server) finishedRun(ctx context.Context, id int64) (store.RunSummary, error) {
	run, err := s.d.Store.Run(ctx, id)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return run, &runError{code: http.StatusNotFound, title: "Run not found",
			text: fmt.Sprintf("There is no run #%d.", id)}
	case err != nil:
		return run, err
	}
	ref := fmt.Sprintf("Run #%d", id)
	switch run.Status {
	case store.RunDone:
		return run, nil
	case store.RunFailed:
		return run, &runError{code: http.StatusBadRequest, title: "Run failed",
			text: ref + " failed, so its results are incomplete. Only finished runs can be shown as an inventory."}
	case store.RunCancelled:
		return run, &runError{code: http.StatusBadRequest, title: "Run cancelled",
			text: ref + " was cancelled, so its results are partial. Only finished runs can be shown as an inventory."}
	}
	return run, &runError{code: http.StatusBadRequest, title: "Run not finished",
		text: ref + " has not finished yet. Its inventory can be shown once it is done."}
}

// requestAsOf resolves the run parameter of an asset page: nil without one,
// a *runError for a run the time machine refuses. href builds the same page
// as of another run (0 = the latest view) for the banner's navigation.
func (s *Server) requestAsOf(r *http.Request, href func(run int64) string) (*AsOf, error) {
	id, err := parseRunParam(r.URL.Query())
	if err != nil || id == 0 {
		return nil, err
	}
	ctx := r.Context()
	run, err := s.finishedRun(ctx, id)
	if err != nil {
		return nil, err
	}
	a := &AsOf{RunID: run.ID, Profile: run.ConfigName, Import: run.Kind == "import", Compared: run.Applied,
		LatestHref: href(0), CanExport: auth.Can(ctx, auth.PermExport)}
	switch {
	case run.FinishedAt != nil:
		a.FinishedAt = *run.FinishedAt
	case run.StartedAt != nil:
		a.FinishedAt = *run.StartedAt
	}
	if !a.FinishedAt.IsZero() {
		a.When = a.FinishedAt.UTC().Format("2006-01-02 15:04") + " UTC"
	}
	if run.Applied {
		cr, err := s.d.Store.ChangeRun(ctx, run.ID)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return nil, fmt.Errorf("change run: %w", err)
		}
		a.BaseRunID = cr.PrevRunID
	}
	switch {
	case a.Import:
		a.Narrow = "An import holds only the hosts of its file, not the whole inventory."
	case run.ConfigID != nil:
		cfg, err := s.d.Store.ScanConfig(ctx, *run.ConfigID)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return nil, fmt.Errorf("scan profile: %w", err)
		}
		if len(cfg.TargetIDs) > 0 {
			a.Narrow = "Its profile covers only some targets: hosts outside them are not in this view."
		}
	}
	if a.OlderID, a.NewerID, err = s.d.Store.AdjacentDoneRuns(ctx, run.ID); err != nil {
		return nil, fmt.Errorf("adjacent runs: %w", err)
	}
	if a.OlderID != 0 {
		a.OlderHref = href(a.OlderID)
	}
	if a.NewerID != 0 {
		a.NewerHref = href(a.NewerID)
	}
	return a, nil
}

// runErrorPage writes the page of a refused run parameter, or the 500 page
// for any other error.
func (s *Server) runErrorPage(w http.ResponseWriter, r *http.Request, err error) {
	var re *runError
	if errors.As(err, &re) {
		s.renderError(w, r, errorData{Code: re.code, Title: re.title, Text: re.text})
		return
	}
	s.log.Error("time machine", "err", err)
	s.serverError(w, r)
}

// notInRun writes the 404 page of an asset that run did not see.
func (s *Server) notInRun(w http.ResponseWriter, r *http.Request, key model.AssetKey, runID int64) {
	what := "this host"
	if key.Port != 0 {
		what = "this service"
	}
	s.renderError(w, r, errorData{Code: http.StatusNotFound, Title: fmt.Sprintf("Not seen in run #%d", runID),
		Text: fmt.Sprintf("Run #%d did not see %s. It may have appeared later, been down at the time, or lie outside what the run covered.", runID, what),
		Links: []ErrorLink{
			{Href: assetsPathAt(url.Values{}, runID), Label: fmt.Sprintf("Inventory as of run #%d", runID)},
			{Href: assetPath(key), Label: "Latest view of " + what},
		}})
}

// withRun adds run (when not 0) to the query of a local path.
func withRun(path string, run int64) string {
	if run == 0 {
		return path
	}
	u, err := url.Parse(path)
	if err != nil {
		return path
	}
	q := u.Query()
	q.Set("run", strconv.FormatInt(run, 10))
	u.RawQuery = q.Encode()
	return u.String()
}

// assetPathAt is assetPath as of run (0 = the latest view).
func assetPathAt(k model.AssetKey, run int64) string { return withRun(assetPath(k), run) }

// assetsPathAt is the asset list with query q as of run (0 = latest).
func assetsPathAt(q url.Values, run int64) string {
	v := url.Values{}
	for k, vs := range q {
		v[k] = vs
	}
	if run != 0 {
		v.Set("run", strconv.FormatInt(run, 10))
	}
	if len(v) == 0 {
		return "/assets"
	}
	return "/assets?" + v.Encode()
}

// values is the filter as a query, without the defaults.
func (f assetFilter) values() url.Values {
	v := url.Values{}
	if f.Text != "" {
		v.Set("q", f.Text)
	}
	if f.State != "" {
		v.Set("state", string(f.State))
	}
	if f.Min > 0 {
		v.Set("min", strconv.Itoa(f.Min))
	}
	if f.Quick != "" {
		v.Set("quick", f.Quick)
	}
	return v
}

// runStateFilters are the host states a past run can tell: whether it got
// an answer.
var runStateFilters = []model.HostStateKind{model.HostUp, model.HostDown}

// runPicker lists recent finished runs, the shown one (0 = latest)
// selected; a shown run older than the list is added to it.
func (s *Server) runPicker(ctx context.Context, shown *AsOf) ([]RunOption, error) {
	runs, err := s.d.Store.DoneRuns(ctx, pickerRuns)
	if err != nil {
		return nil, fmt.Errorf("finished runs: %w", err)
	}
	var out []RunOption
	found := false
	for _, run := range runs {
		o := RunOption{ID: run.ID, Label: runOptionLabel(run)}
		if shown != nil && run.ID == shown.RunID {
			o.Selected, found = true, true
		}
		out = append(out, o)
	}
	if shown != nil && !found {
		run := store.RunSummary{ID: shown.RunID, ConfigName: shown.Profile, Kind: "scan", FinishedAt: &shown.FinishedAt}
		if shown.Import {
			run.Kind = "import"
		}
		out = append(out, RunOption{ID: shown.RunID, Label: runOptionLabel(run), Selected: true})
	}
	return out, nil
}

// runOptionLabel is "#12 · 2026-11-24 10:00 UTC · Lab nightly".
func runOptionLabel(r store.RunSummary) string {
	l := "#" + strconv.FormatInt(r.ID, 10)
	switch {
	case r.FinishedAt != nil && !r.FinishedAt.IsZero():
		l += " · " + r.FinishedAt.UTC().Format("2006-01-02 15:04") + " UTC"
	case r.StartedAt != nil:
		l += " · " + r.StartedAt.UTC().Format("2006-01-02 15:04") + " UTC"
	}
	switch {
	case r.Kind == "import":
		l += " · import"
	case r.ConfigName != "":
		l += " · " + r.ConfigName
	}
	return l
}

// loadSnapshotAt builds the snapshot of finished run runID as that run saw
// it: its hosts (up = answered; down = recorded without an answer, or
// reported down by the run's diff), its services scored with the run's own
// changes, and today's notes.
func (s *Server) loadSnapshotAt(ctx context.Context, runID int64) (snapshot, error) {
	snap := newSnapshot()
	snap.RunID = runID
	changes, hosts, svcs, err := s.loadRunObs(ctx, runID)
	if err != nil {
		return snap, err
	}
	snap.States = runStates(hosts, svcs, changes)
	unstable := map[netip.Addr]bool{}
	for _, c := range changes {
		if c.Kind == model.ChangeUnstable && c.Key.Port == 0 {
			unstable[c.Key.IP.Unmap()] = true
		}
	}
	if err := s.loadNotes(ctx, &snap); err != nil {
		return snap, err
	}
	snap.addRun(changes, hosts, svcs, unstable)
	return snap, nil
}

// runStates are the hosts of one run as host states: up when the run got
// an answer (or found an open service), down when it recorded the host
// without an answer or its diff reported the host down. LastSeen is left
// zero: the run does not say when a down host was last seen.
func runStates(hosts []model.HostObs, svcs []store.ExportService, changes []model.Change) []model.HostState {
	byIP := map[netip.Addr]model.HostStateKind{}
	for _, h := range hosts {
		switch ip := h.IP.Unmap(); {
		case h.Up:
			byIP[ip] = model.HostUp
		case byIP[ip] == "":
			byIP[ip] = model.HostDown
		}
	}
	for _, sv := range svcs {
		byIP[sv.Key.IP.Unmap()] = model.HostUp
	}
	for _, c := range changes {
		if ip := c.Key.IP.Unmap(); c.Kind == model.ChangeHostDown && byIP[ip] == "" {
			byIP[ip] = model.HostDown
		}
	}
	out := make([]model.HostState, 0, len(byIP))
	for ip, st := range byIP {
		out = append(out, model.HostState{IP: ip, State: st})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IP.Less(out[j].IP) })
	return out
}

// runStateLabel describes what run saw of a host.
func runStateLabel(st model.HostStateKind, run int64) string {
	if st == model.HostUp {
		return fmt.Sprintf("up in run #%d", run)
	}
	return fmt.Sprintf("no answer in run #%d", run)
}
