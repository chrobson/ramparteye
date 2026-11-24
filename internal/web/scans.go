package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/chrobson/ramparteye/internal/auth"
	"github.com/chrobson/ramparteye/internal/dojo"
	"github.com/chrobson/ramparteye/internal/safety"
	"github.com/chrobson/ramparteye/internal/store"
)

const (
	scansListLen      = 50 // runs on the scans page
	manualPushTimeout = 2 * time.Minute
)

// RunRow is a run on the scans page.
type RunRow struct {
	ID          int64
	Profile     string
	Kind        string
	Status      RunStatus
	Progress    string // "3/4 chunks" ("" when the run has no chunks)
	ChunksFail  int
	HostsUp     int
	Services    int
	StartedAt   time.Time
	Duration    string
	Applied     bool
	Active      bool
	FinishedRun bool // done: its results can be pushed and exported
}

// RunStatus is a run status as shown in the UI.
type RunStatus struct {
	Key   string // store status
	Label string
	Class string // tag class
	Note  string // longer explanation on the run page
}

// runStatus describes a run's status.
func runStatus(status string) RunStatus {
	st := RunStatus{Key: status, Label: status, Class: "tag-changed"}
	switch status {
	case store.RunQueued:
		st.Label, st.Note = "Queued", "Waiting for a scan worker or its time window."
	case store.RunRunning:
		st.Label, st.Class = "Running", "tag-up"
	case store.RunPaused:
		st.Label, st.Class = "Paused (waiting for its time window)", "tag-flap"
		st.Note = "The run did not finish inside its time window. Unfinished chunks continue in the next window."
	case store.RunDone:
		st.Label, st.Class = "Done", "tag-up"
	case store.RunFailed:
		st.Label, st.Class = "Failed", "tag-gone"
		st.Note = "The run failed. Check the server log; finished chunks are kept but changes were not compared."
	case store.RunCancelled:
		st.Label, st.Class = "Cancelled", "tag-gone"
		st.Note = "This run was cancelled. Its partial results are kept, but changes were not compared and nothing was pushed to DefectDojo."
	}
	return st
}

// durationText formats a run duration: "45 s", "8 min", "2 h 5 min".
func durationText(ms *int64) string {
	if ms == nil || *ms < 0 {
		return ""
	}
	d := time.Duration(*ms) * time.Millisecond
	switch {
	case d < time.Minute:
		return strconv.Itoa(int(d/time.Second)) + " s"
	case d < time.Hour:
		return strconv.Itoa(int(d/time.Minute)) + " min"
	default:
		return fmt.Sprintf("%d h %d min", int(d/time.Hour), int(d%time.Hour/time.Minute))
	}
}

func (s *Server) runRow(r store.RunSummary, active map[int64]bool) RunRow {
	row := RunRow{ID: r.ID, Profile: r.ConfigName, Kind: r.Kind, Status: runStatus(r.Status),
		ChunksFail: r.ChunksFailed, HostsUp: r.HostsUp, Services: r.Services, Duration: durationText(r.DurationMS),
		Applied: r.Applied, Active: active[r.ID], FinishedRun: r.Status == store.RunDone}
	if r.StartedAt != nil {
		row.StartedAt = *r.StartedAt
	}
	if r.ChunksTotal > 0 {
		row.Progress = fmt.Sprintf("%d/%d chunks", r.ChunksDone, r.ChunksTotal)
	}
	return row
}

func (s *Server) activeSet() map[int64]bool {
	out := map[int64]bool{}
	if s.d.Runner != nil {
		for _, id := range s.d.Runner.ActiveRuns() {
			out[id] = true
		}
	}
	return out
}

// ScansData is the scans page.
type ScansData struct {
	Title   string
	Runs    []RunRow
	Polling bool // a run is unfinished: the list refreshes itself
}

func (s *Server) scansList(w http.ResponseWriter, r *http.Request) {
	runs, err := s.d.Store.Runs(r.Context(), scansListLen)
	if err != nil {
		s.log.Error("list runs", "err", err)
		s.serverError(w, r)
		return
	}
	active := s.activeSet()
	d := ScansData{Title: "Scans"}
	for _, run := range runs {
		row := s.runRow(run, active)
		d.Polling = d.Polling || row.Active || run.Status == store.RunRunning || run.Status == store.RunQueued
		d.Runs = append(d.Runs, row)
	}
	s.render(w, r, "scans", d)
}

// CheckView is one safety check on the receipt.
type CheckView struct {
	Name     string
	Status   safety.Status
	Label    string
	Class    string
	Measured string
	Detail   string
}

// ReceiptView is the safety receipt panel of a run.
type ReceiptView struct {
	Missing     bool
	Status      safety.ReportStatus
	StatusLabel string
	StatusClass string
	Report      safety.Report
	Checks      []CheckView
	ArgvShort   string
}

func receiptView(rep safety.Report) ReceiptView {
	v := ReceiptView{Status: rep.Status, Report: rep, ArgvShort: truncate(rep.ArgvSHA256, 12)}
	switch rep.Status {
	case safety.ReportOK:
		v.StatusLabel, v.StatusClass = "All safety checks passed", "check-pass"
	case safety.ReportIncomplete:
		v.StatusLabel, v.StatusClass = "Incomplete: some checks could not be measured", "check-unmeasured"
	default:
		v.StatusLabel, v.StatusClass = "A safety check failed", "check-fail"
	}
	for _, c := range rep.Checks {
		cv := CheckView{Name: c.Name, Status: c.Status, Measured: c.Measured, Detail: c.Detail}
		switch c.Status {
		case safety.StatusPass:
			cv.Label, cv.Class = "pass", "check-pass"
		case safety.StatusFail:
			cv.Label, cv.Class = "fail", "check-fail"
		default:
			cv.Label, cv.Class = "unmeasured", "check-unmeasured"
		}
		v.Checks = append(v.Checks, cv)
	}
	return v
}

// RunPage is the data of /scans/{id}.
type RunPage struct {
	Title   string
	Run     RunRow
	Receipt ReceiptView
}

// pathID parses a positive decimal id from the URL parameter name.
func pathID(r *http.Request, name string) (int64, bool) {
	id, err := strconv.ParseInt(chi.URLParam(r, name), 10, 64)
	return id, err == nil && id > 0
}

// loadRun returns the run of the {id} parameter; ok is false (and a page
// written) when it is invalid, unknown or failed to load.
func (s *Server) loadRun(w http.ResponseWriter, r *http.Request) (store.RunSummary, bool) {
	id, ok := pathID(r, "id")
	if !ok {
		s.notFound(w, r)
		return store.RunSummary{}, false
	}
	run, err := s.d.Store.Run(r.Context(), id)
	switch {
	case errors.Is(err, store.ErrNotFound):
		s.notFound(w, r)
		return run, false
	case err != nil:
		s.log.Error("load run", "run", id, "err", err)
		s.serverError(w, r)
		return run, false
	}
	return run, true
}

// loadReport builds the safety report of a run; ok is false without a
// stored receipt.
func (s *Server) loadReport(ctx context.Context, runID int64) (safety.Report, bool, error) {
	rc, err := s.d.Store.SafetyReceipt(ctx, runID)
	switch {
	case errors.Is(err, safety.ErrNoReceipt):
		return safety.Report{}, false, nil
	case err != nil:
		return safety.Report{}, false, err
	}
	return safety.BuildReport(rc), true, nil
}

func (s *Server) runPage(w http.ResponseWriter, r *http.Request) {
	run, ok := s.loadRun(w, r)
	if !ok {
		return
	}
	p := RunPage{Title: "Scan #" + strconv.FormatInt(run.ID, 10), Run: s.runRow(run, s.activeSet())}
	rep, found, err := s.loadReport(r.Context(), run.ID)
	if err != nil {
		s.log.Error("load safety receipt", "run", run.ID, "err", err)
		s.serverError(w, r)
		return
	}
	if found {
		p.Receipt = receiptView(rep)
	} else {
		p.Receipt.Missing = true
	}
	s.render(w, r, "run", p)
}

// safetyJSON serves the safety report of a run (the same body as
// `ramparteye audit <run>`).
func (s *Server) safetyJSON(w http.ResponseWriter, r *http.Request) {
	run, ok := s.loadRun(w, r)
	if !ok {
		return
	}
	rep, found, err := s.loadReport(r.Context(), run.ID)
	switch {
	case err != nil:
		s.log.Error("load safety receipt", "run", run.ID, "err", err)
		s.serverError(w, r)
		return
	case !found:
		s.notFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(rep)
}

// runPush pushes one finished run to DefectDojo and reports the outcome in
// a flash message.
func (s *Server) runPush(w http.ResponseWriter, r *http.Request) {
	run, ok := s.loadRun(w, r)
	if !ok {
		return
	}
	back := "/scans/" + strconv.FormatInt(run.ID, 10)
	if run.Status != store.RunDone {
		setFlash(w, r, "Only finished runs can be pushed to DefectDojo.")
		http.Redirect(w, r, back, http.StatusSeeOther)
		return
	}
	msg := "DefectDojo is not configured. An administrator can set it up in Settings."
	if s.d.Pusher != nil {
		// The push finishes and is recorded even if the browser goes away.
		ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), manualPushTimeout)
		rec, err := s.d.Pusher.PushRun(ctx, run.ID, dojo.TriggerManual)
		cancel()
		msg = pushMessage(run.ID, rec, err)
		u, _ := auth.CurrentUser(r.Context())
		s.audit(r, &u.ID, "dojo.push", "scan_run:"+strconv.FormatInt(run.ID, 10),
			map[string]any{"trigger": dojo.TriggerManual, "ok": err == nil})
		if err != nil && !errors.Is(err, dojo.ErrNotConfigured) && !errors.Is(err, dojo.ErrStaleRun) {
			s.log.Warn("manual DefectDojo push", "run", run.ID, "err", err)
		}
	}
	setFlash(w, r, msg)
	http.Redirect(w, r, back, http.StatusSeeOther)
}

func pushMessage(runID int64, rec dojo.PushRecord, err error) string {
	switch {
	case errors.Is(err, dojo.ErrNotConfigured):
		return "DefectDojo is not configured. An administrator can set it up in Settings."
	case errors.Is(err, dojo.ErrStaleRun):
		return "Not pushed: a newer run of this scan profile has already been pushed."
	case err != nil && rec.Error != "":
		return "Push to DefectDojo failed: " + rec.Error
	case err != nil:
		return "Push to DefectDojo failed: " + err.Error()
	}
	return fmt.Sprintf("Pushed %s of run #%d to DefectDojo: %d new, %d closed.",
		plural(rec.Findings, "finding", "findings"), runID, rec.Added, rec.Closed)
}
