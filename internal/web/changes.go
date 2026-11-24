package web

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/chrobson/ramparteye/internal/diff"
	"github.com/chrobson/ramparteye/internal/model"
	"github.com/chrobson/ramparteye/internal/store"
)

// Change timeline geometry (SVG user units, viewBox 0 0 720 200).
const (
	timelineRuns  = 30 // at most this many runs, the newest kept
	changeRunsLen = 100

	chartLeft   = 40.0
	chartRight  = 710.0
	chartTop    = 10.0
	chartBottom = 170.0 // baseline; run labels below it
)

// kindLabels are the display names of change kinds.
var kindLabels = map[model.ChangeKind]string{
	model.ChangeNew:      "New",
	model.ChangeGone:     "Gone",
	model.ChangeChanged:  "Changed",
	model.ChangeHostUp:   "Host up",
	model.ChangeHostDown: "Host down",
	model.ChangeUnstable: "Unstable",
}

// timelineClasses colour the change kinds on the timeline (literal class
// names so the Tailwind build keeps them).
var timelineClasses = map[model.ChangeKind]string{
	model.ChangeNew:      "tl-new",
	model.ChangeGone:     "tl-gone",
	model.ChangeChanged:  "tl-changed",
	model.ChangeHostUp:   "tl-host_up",
	model.ChangeHostDown: "tl-host_down",
	model.ChangeUnstable: "tl-unstable",
}

func kindLabel(k model.ChangeKind) string {
	if l, ok := kindLabels[k]; ok {
		return l
	}
	return string(k)
}

// fieldLabels name the compared service fields.
var fieldLabels = map[string]string{
	"product": "product", "version": "version", "extrainfo": "extra info", "cpe": "CPE",
	"banner": "service", "flips": "state changes", diff.LatencyField: "HTTP response time",
	diff.GatewayField: "HTTP status",
}

func fieldLabel(f string) string {
	if l, ok := fieldLabels[f]; ok {
		return l
	}
	return f
}

// TimelineSegment is one change kind's part of a run's stacked bar.
type TimelineSegment struct {
	Kind  model.ChangeKind
	Class string
	Count int
	Y, H  float64
}

// TimelineBar is one run on the timeline: a clickable slot (full height, also for
// runs without changes) with stacked segments in diff.KindOrder.
type TimelineBar struct {
	RunID        int64
	SlotX, SlotW float64
	X, W         float64
	LabelX       float64
	Total        int
	Title        string
	Segments     []TimelineSegment
}

// Timeline is the change timeline (inline SVG): bars of changes per run and
// lines of hosts up and services.
type Timeline struct {
	Bars         []TimelineBar
	HostsLine    string // polyline points
	ServicesLine string
	MaxChanges   int
	MaxAssets    int
	Top, Bottom  float64
}

// Enough reports whether there are at least two runs to compare.
func (c Timeline) Enough() bool { return len(c.Bars) >= 2 }

// buildTimeline lays out up to timelineRuns points (oldest first): one
// stacked bar per run scaled to the largest change total, and polylines for
// hosts up and services scaled to the largest of the two.
func buildTimeline(points []store.RunPoint) Timeline {
	if len(points) > timelineRuns {
		points = points[len(points)-timelineRuns:]
	}
	c := Timeline{Top: chartTop, Bottom: chartBottom}
	if len(points) == 0 {
		return c
	}
	totals := make([]int, len(points))
	for i, p := range points {
		for _, k := range diff.KindOrder {
			totals[i] += p.Counts[k]
		}
		c.MaxChanges = max(c.MaxChanges, totals[i])
		c.MaxAssets = max(c.MaxAssets, p.HostsUp, p.Services)
	}
	plotH := chartBottom - chartTop
	slot := (chartRight - chartLeft) / float64(len(points))
	barW := slot * 0.6
	var hosts, svcs []string
	for i, p := range points {
		b := TimelineBar{RunID: p.RunID, SlotX: chartLeft + float64(i)*slot, SlotW: slot, W: barW, Total: totals[i]}
		b.X = b.SlotX + (slot-barW)/2
		b.LabelX = b.SlotX + slot/2
		y := chartBottom
		var parts []string
		for _, k := range diff.KindOrder {
			n := p.Counts[k]
			if n == 0 {
				continue
			}
			h := plotH * float64(n) / float64(c.MaxChanges)
			y -= h
			b.Segments = append(b.Segments, TimelineSegment{Kind: k, Class: timelineClasses[k], Count: n, Y: y, H: h})
			parts = append(parts, kindLabel(k)+" "+strconv.Itoa(n))
		}
		if len(parts) == 0 {
			parts = []string{"no changes"}
		}
		b.Title = fmt.Sprintf("Run #%d, %s: %s; hosts up %d, services %d", p.RunID,
			p.StartedAt.UTC().Format("2006-01-02 15:04")+" UTC", strings.Join(parts, ", "), p.HostsUp, p.Services)
		c.Bars = append(c.Bars, b)
		hosts = append(hosts, point(b.LabelX, assetY(p.HostsUp, c.MaxAssets)))
		svcs = append(svcs, point(b.LabelX, assetY(p.Services, c.MaxAssets)))
	}
	c.HostsLine, c.ServicesLine = strings.Join(hosts, " "), strings.Join(svcs, " ")
	return c
}

func assetY(v, maxV int) float64 {
	if maxV == 0 {
		return chartBottom
	}
	return chartBottom - (chartBottom-chartTop)*float64(v)/float64(maxV)
}

func point(x, y float64) string { return fmt.Sprintf("%.1f,%.1f", x, y) }

// f1 formats an SVG coordinate.
func f1(v float64) string { return strconv.FormatFloat(v, 'f', 1, 64) }

// ChangeRunRow is a run on the changes overview.
type ChangeRunRow struct {
	RunID      int64
	PrevRunID  int64
	Kind       string
	Status     RunStatus
	FinishedAt time.Time
	Applied    bool
	Counts     []int // per diff.KindOrder
	Total      int
}

// StateCount is a host state with its count.
type StateCount struct {
	State model.HostStateKind
	Class string
	Count int
}

// UnstableHost is a host on the unstable list.
type UnstableHost struct {
	IP       string
	Flips    []RunCell
	Changes  int
	LastSeen time.Time
}

// ChangesData is the changes overview.
type ChangesData struct {
	Title    string
	Kinds    []KindView
	Runs     []ChangeRunRow
	States   []StateCount
	Unstable []UnstableHost
	Timeline Timeline
	// Thresholds of the host states, for the explanation.
	InactiveAfter, UnstableFlips, Window int
}

// KindView is a change kind with its label and tag class.
type KindView struct {
	Kind    model.ChangeKind
	Label   string
	Class   string
	TLClass string
}

func kindViews() []KindView {
	out := make([]KindView, len(diff.KindOrder))
	for i, k := range diff.KindOrder {
		out[i] = KindView{Kind: k, Label: kindLabel(k), Class: changeClass(k), TLClass: timelineClasses[k]}
	}
	return out
}

func (s *Server) changesPage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	st := s.d.Store
	runs, err := st.ChangeRuns(ctx, changeRunsLen)
	if err != nil {
		s.log.Error("change runs", "err", err)
		s.serverError(w, r)
		return
	}
	counts, err := st.HostStateCounts(ctx)
	if err != nil {
		s.log.Error("host state counts", "err", err)
		s.serverError(w, r)
		return
	}
	series, err := st.RunSeries(ctx, timelineRuns)
	if err != nil {
		s.log.Error("run series", "err", err)
		s.serverError(w, r)
		return
	}
	unstable, err := st.HostStates(ctx, model.HostUnstable)
	if err != nil {
		s.log.Error("unstable hosts", "err", err)
		s.serverError(w, r)
		return
	}
	u := s.d.Cfg.Unstable
	d := ChangesData{Title: "Changes", Kinds: kindViews(), Timeline: buildTimeline(series),
		InactiveAfter: u.InactiveAfterMisses, UnstableFlips: u.UnstableIfFlips, Window: u.Window}
	for _, k := range hostStateFilters {
		d.States = append(d.States, StateCount{State: k, Class: stateClass(k), Count: counts[k]})
	}
	for _, cr := range runs {
		row := ChangeRunRow{RunID: cr.RunID, PrevRunID: cr.PrevRunID, Kind: cr.Kind,
			Status: runStatus(cr.Status, false), Applied: cr.Applied, Total: cr.Total}
		if cr.FinishedAt != nil {
			row.FinishedAt = *cr.FinishedAt
		}
		for _, k := range diff.KindOrder {
			row.Counts = append(row.Counts, cr.Counts[k])
		}
		d.Runs = append(d.Runs, row)
	}
	for _, h := range unstable {
		uh := UnstableHost{IP: h.IP.Unmap().String(), Changes: diff.Transitions(h.Flips), LastSeen: h.LastSeen}
		for _, f := range h.Flips {
			c := RunCell{Class: "run-down", Label: fmt.Sprintf("Run #%d: no answer", f.RunID)}
			if f.Up {
				c = RunCell{Class: "run-up", Label: fmt.Sprintf("Run #%d: answered", f.RunID)}
			}
			uh.Flips = append(uh.Flips, c)
		}
		d.Unstable = append(d.Unstable, uh)
	}
	s.render(w, r, "changes", d)
}

// ChangeGroup is the changes of one kind in a run.
type ChangeGroup struct {
	Kind  model.ChangeKind
	Label string
	Class string
	Rows  []ChangeLine
}

// ChangeLine is one change on the run changes page.
type ChangeLine struct {
	Href     string
	Endpoint string
	VHost    string
	Field    string
	Old, New string
}

// ChangeRunPage is the data of /changes/{run}.
type ChangeRunPage struct {
	Title  string
	Run    ChangeRunRow
	Total  int
	Groups []ChangeGroup
}

func (s *Server) changeRunPage(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r, "run")
	if !ok {
		s.notFound(w, r)
		return
	}
	ctx := r.Context()
	cr, err := s.d.Store.ChangeRun(ctx, id)
	switch {
	case errors.Is(err, store.ErrNotFound):
		s.notFound(w, r)
		return
	case err != nil:
		s.log.Error("change run", "run", id, "err", err)
		s.serverError(w, r)
		return
	}
	cs, err := s.d.Store.Changes(ctx, id)
	if err != nil {
		s.log.Error("changes", "run", id, "err", err)
		s.serverError(w, r)
		return
	}
	diff.SortChanges(cs)
	p := ChangeRunPage{Title: "Changes in run #" + strconv.FormatInt(id, 10), Total: len(cs),
		Run: ChangeRunRow{RunID: cr.RunID, PrevRunID: cr.PrevRunID, Kind: cr.Kind,
			Status: runStatus(cr.Status, false), Applied: cr.Applied}}
	by := map[model.ChangeKind][]ChangeLine{}
	for _, c := range cs {
		by[c.Kind] = append(by[c.Kind], ChangeLine{Href: assetPath(c.Key), Endpoint: endpoint(c.Key),
			VHost: c.Key.VHost, Field: fieldLabel(c.Field), Old: c.Old, New: c.New})
	}
	for _, k := range diff.KindOrder {
		if rows := by[k]; len(rows) > 0 {
			p.Groups = append(p.Groups, ChangeGroup{Kind: k, Label: kindLabel(k), Class: changeClass(k), Rows: rows})
		}
	}
	s.render(w, r, "changerun", p)
}
