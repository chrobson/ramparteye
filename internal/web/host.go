package web

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/chrobson/ramparteye/internal/diff"
	"github.com/chrobson/ramparteye/internal/dojo"
	"github.com/chrobson/ramparteye/internal/model"
	"github.com/chrobson/ramparteye/internal/store"
)

// errNotFound is returned by the page loaders for an unknown asset.
var errNotFound = errors.New("asset not found")

var weekdays = [7]string{"Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"}

// RunCell is one square of a runs strip.
type RunCell struct {
	Class string // run-up | run-down | run-na
	Label string
}

// HeatCell is one weekday/hour cell of the availability heatmap.
type HeatCell struct {
	Day, Hour int
	Class     string // heat-none | heat-miss | heat-1 | heat-2 | heat-3
	Label     string
}

// HeatRow is one weekday of the heatmap.
type HeatRow struct {
	Day   string // short name
	Cells []HeatCell
}

// BandView is a time-of-day band.
type BandView struct {
	Label string // "06–12"
	Text  string // "2/4" or "—"
	Class string // band-hi | band-mid | band-lo | band-none
}

// AvailView is the availability panel.
type AvailView struct {
	HasData    bool
	Summary    string // "Availability 4/6 · pattern intermittent"
	Pattern    string
	Seen       int
	Total      int
	Misses     int    // trailing covered runs in which the asset was not seen
	Plain      string // one-line plain-language summary
	Runs       []RunCell
	Heat       []HeatRow
	HourLabels []string
	Bands      []BandView
	Lookback   int
}

// ChangeRow is a change of one asset.
type ChangeRow struct {
	RunID  int64
	Kind   model.ChangeKind
	Detail string
}

// ServiceRow is a service on the host page.
type ServiceRow struct {
	Href       string
	Port       string // "80/tcp"
	VHost      string
	Product    string
	Detections []DetectionBadge
	Score      int
	Reasons    []ReasonView
	Noted      bool
}

// FindingRow is a detection with its classification and remediation.
type FindingRow struct {
	Port        string
	Name        string
	Severity    model.Severity
	CWE         []int
	Attack      []string
	Remediation string
}

// HostPage is the data of /assets/{ip}.
type HostPage struct {
	Title     string
	IP        string
	Hostname  string
	State     model.HostStateKind
	StateCls  string
	FirstSeen time.Time
	LastSeen  time.Time
	Avail     AvailView
	Changes   []ChangeRow
	Services  []ServiceRow
	Findings  []FindingRow
	Note      AnnotationForm
	// InactiveAfter is the number of misses after which a host is marked inactive.
	InactiveAfter int
}

func availView(runs []store.AssetRun) AvailView {
	pres := make([]diff.RunPresence, len(runs))
	v := AvailView{Lookback: availabilityRuns}
	for i, r := range runs {
		pres[i] = diff.RunPresence{At: r.StartedAt, Covered: r.Covered, Seen: r.Seen}
		c := RunCell{Class: "run-na", Label: "not covered by this scan"}
		switch {
		case r.Seen:
			c.Class, c.Label = "run-up", "seen"
		case r.Covered:
			c.Class, c.Label = "run-down", "not seen"
		}
		c.Label = fmt.Sprintf("Run #%d, %s UTC: %s", r.RunID, r.StartedAt.UTC().Format("2006-01-02 15:04"), c.Label)
		v.Runs = append(v.Runs, c)
	}
	a := diff.ComputeAvailability(pres, time.UTC)
	v.Pattern, v.Seen, v.Total, v.Plain = a.Pattern, a.Seen, a.Total, plainSummary(a)
	for i := len(runs) - 1; i >= 0; i-- {
		if !runs[i].Covered {
			continue // says nothing about availability
		}
		if runs[i].Seen {
			break
		}
		v.Misses++
	}
	v.HasData = a.Total > 0
	v.Summary = fmt.Sprintf("Availability %d/%d · pattern %s", a.Seen, a.Total, a.Pattern)
	for h := range 24 {
		l := ""
		if h%3 == 0 {
			l = fmt.Sprintf("%02d", h)
		}
		v.HourLabels = append(v.HourLabels, l)
	}
	for d := range 7 {
		row := HeatRow{Day: weekdays[d][:3]}
		for h := range 24 {
			row.Cells = append(row.Cells, heatCell(d, h, a.Week[d][h]))
		}
		v.Heat = append(v.Heat, row)
	}
	for _, b := range a.ByBand {
		bv := BandView{Label: fmt.Sprintf("%02d–%02d", b.From, b.To), Text: "—", Class: "band-" + b.Level()}
		if b.Total > 0 {
			bv.Text = fmt.Sprintf("%d/%d", b.Seen, b.Total)
		}
		v.Bands = append(v.Bands, bv)
	}
	return v
}

// plainSummary describes the availability pattern in one sentence. It is
// deterministic: the same Availability always gives the same text.
func plainSummary(a diff.Availability) string {
	switch a.Pattern {
	case diff.PatternAlways:
		return "Seen in every scan that covered it."
	case diff.PatternOfficeHours:
		end := "rarely outside those hours"
		weekend := 0
		for _, d := range []int{5, 6} {
			for _, c := range a.Week[d] {
				weekend += c.Seen
			}
		}
		if weekend == 0 {
			end = "never at weekends"
		}
		return "Up mostly 07–17 on weekdays, " + end + "."
	case diff.PatternIntermittent:
		return fmt.Sprintf("Seen in %d of %d scans, with no time-of-day pattern.", a.Seen, a.Total)
	case diff.PatternIrregular:
		return fmt.Sprintf("Seen in only %d of %d scans.", a.Seen, a.Total)
	}
	return ""
}

func heatCell(day, hour int, c diff.Cell) HeatCell {
	hc := HeatCell{Day: day, Hour: hour}
	when := fmt.Sprintf("%s %02d:00", weekdays[day], hour)
	switch {
	case c.Total == 0:
		hc.Class, hc.Label = "heat-none", when+", no runs"
		return hc
	case c.Seen == 0:
		hc.Class = "heat-miss"
	default:
		switch rate := c.Seen * 100 / c.Total; {
		case rate < 34:
			hc.Class = "heat-1"
		case rate < 67:
			hc.Class = "heat-2"
		default:
			hc.Class = "heat-3"
		}
	}
	hc.Label = fmt.Sprintf("%s, seen in %d of %s", when, c.Seen, plural(c.Total, "run", "runs"))
	return hc
}

func changeRows(cs []model.Change) []ChangeRow {
	out := make([]ChangeRow, len(cs))
	for i, c := range cs {
		out[i] = ChangeRow{RunID: c.RunID, Kind: c.Kind, Detail: changeDetail(c)}
	}
	return out
}

func portLabel(k model.AssetKey) string { return strconv.Itoa(int(k.Port)) + "/" + k.Proto }

func productLabel(sv store.ExportService) string {
	p := strings.TrimSpace(sv.Product + " " + sv.Version)
	if p == "" {
		p = sv.Banner
	}
	return p
}

// hostPage renders GET /assets/{ip}.
func (s *Server) hostPage(w http.ResponseWriter, r *http.Request) {
	ip, ok := parseIP(chi.URLParam(r, "ip"))
	if !ok {
		s.notFound(w, r)
		return
	}
	s.renderHost(w, r, http.StatusOK, ip, nil)
}

// renderHost loads and renders the host page; form, when set, replaces the
// stored annotation in the form (a rejected submission).
func (s *Server) renderHost(w http.ResponseWriter, r *http.Request, status int, ip netip.Addr, form *AnnotationForm) {
	p, err := s.loadHost(r.Context(), ip, form)
	switch {
	case errors.Is(err, errNotFound):
		s.notFound(w, r)
	case err != nil:
		s.log.Error("load host page", "err", err)
		s.serverError(w, r)
	default:
		s.renderStatus(w, r, status, "host", p)
	}
}

func (s *Server) loadHost(ctx context.Context, ip netip.Addr, form *AnnotationForm) (HostPage, error) {
	p := HostPage{Title: ip.String(), IP: ip.String(), InactiveAfter: s.d.Cfg.Unstable.InactiveAfterMisses}
	snap, err := s.loadSnapshot(ctx)
	if err != nil {
		return p, err
	}
	var hs *model.HostState
	for i := range snap.States {
		if snap.States[i].IP.Unmap() == ip {
			hs = &snap.States[i]
		}
	}
	if hs == nil {
		return p, errNotFound
	}
	p.State, p.StateCls, p.FirstSeen, p.LastSeen = hs.State, stateClass(hs.State), hs.FirstSeen, hs.LastSeen
	p.Hostname = snap.Hostnames[ip]

	hostKey := model.AssetKey{IP: ip}
	hist, err := s.d.Store.AssetHistory(ctx, hostKey, availabilityRuns)
	if err != nil {
		return p, fmt.Errorf("history: %w", err)
	}
	p.Avail = availView(hist.Runs)
	p.Changes = changeRows(hist.Changes)

	svcs := snap.Services[ip]
	if err := s.attachMeta(ctx, svcs, detectionIDs(svcs)); err != nil {
		return p, err
	}
	sort.SliceStable(svcs, func(i, j int) bool { return svcs[i].Key.Port < svcs[j].Key.Port })
	for _, sv := range svcs {
		_, noted := snap.Notes[sv.Key]
		p.Services = append(p.Services, ServiceRow{Href: assetPath(sv.Key), Port: portLabel(sv.Key),
			VHost: sv.Key.VHost, Product: productLabel(sv.ExportService), Detections: detectionBadges(sv.Detections),
			Score: sv.Result.Score, Reasons: reasonViews(sv.Result), Noted: noted})
		for _, d := range sv.Detections {
			if d.Meta.Empty() {
				continue
			}
			p.Findings = append(p.Findings, FindingRow{Port: portLabel(sv.Key), Name: d.Name,
				Severity: dojo.DetectionSeverity(d), CWE: d.Meta.CWE, Attack: d.Meta.Attack,
				Remediation: d.Meta.Remediation})
		}
	}
	p.Note, err = s.annotationFor(ctx, hostKey, form)
	return p, err
}

// DetectionView is a detection on the service page.
type DetectionView struct {
	Name, SignatureID, Category string
	Severity                    model.Severity
	Confidence                  int
	Outdated                    string
	Evidence                    []KV
	CWE                         []int
	Attack                      []string
	Remediation                 string
}

// KV is a key/value row.
type KV struct{ K, V string }

// HeaderRow is a response header.
type HeaderRow struct {
	Name   string
	Values []string
}

// ServicePage is the data of /assets/{ip}/{port}/{proto}.
type ServicePage struct {
	Title      string
	Endpoint   string
	HostHref   string
	Key        model.AssetKey
	Svc        store.ExportService
	Product    string
	Score      int
	Priority   string
	Reasons    []ReasonView
	Detections []DetectionView
	HTTP       *model.HTTPObs
	Slow       bool
	Headers    []HeaderRow
	Avail      AvailView
	Changes    []ChangeRow
	Note       AnnotationForm
}

// slowResponseMS marks an HTTP response as slow in the UI.
const slowResponseMS = 1000

func (s *Server) servicePage(w http.ResponseWriter, r *http.Request) {
	key, ok := serviceKey(r)
	if !ok {
		s.notFound(w, r)
		return
	}
	s.renderService(w, r, http.StatusOK, key, nil)
}

// serviceKey builds the asset key from the URL: validated ip, port, proto
// and the optional vhost query parameter.
func serviceKey(r *http.Request) (model.AssetKey, bool) {
	ip, ok := parseIP(chi.URLParam(r, "ip"))
	if !ok {
		return model.AssetKey{}, false
	}
	port, ok := parsePort(chi.URLParam(r, "port"))
	proto := chi.URLParam(r, "proto")
	vhost := r.URL.Query().Get("vhost") // matched exactly against stored keys
	if !ok || !protos[proto] {
		return model.AssetKey{}, false
	}
	return model.AssetKey{IP: ip, Port: port, Proto: proto, VHost: vhost}, true
}

func (s *Server) renderService(w http.ResponseWriter, r *http.Request, status int, key model.AssetKey, form *AnnotationForm) {
	p, err := s.loadService(r.Context(), key, form)
	switch {
	case errors.Is(err, errNotFound):
		s.notFound(w, r)
	case err != nil:
		s.log.Error("load service page", "err", err)
		s.serverError(w, r)
	default:
		s.renderStatus(w, r, status, "service", p)
	}
}

func (s *Server) loadService(ctx context.Context, key model.AssetKey, form *AnnotationForm) (ServicePage, error) {
	p := ServicePage{Key: key, Endpoint: endpoint(key), HostHref: assetPath(model.AssetKey{IP: key.IP})}
	p.Title = p.Endpoint + "/" + key.Proto
	snap, err := s.loadSnapshot(ctx)
	if err != nil {
		return p, err
	}
	var sv *scoredService
	svcs := snap.Services[key.IP]
	for i := range svcs {
		if svcs[i].Key == key {
			sv = &svcs[i]
		}
	}
	if sv == nil {
		return p, errNotFound
	}
	if err := s.attachMeta(ctx, svcs, detectionIDs([]scoredService{*sv})); err != nil {
		return p, err
	}
	p.Svc, p.Product = sv.ExportService, productLabel(sv.ExportService)
	p.Score, p.Reasons = sv.Result.Score, reasonViews(sv.Result)
	p.Priority = sv.Result.Priority
	for _, d := range sv.Detections {
		dv := DetectionView{Name: d.Name, SignatureID: d.SignatureID, Category: strings.ReplaceAll(d.Category, "-", " "),
			Severity: dojo.DetectionSeverity(d), Confidence: d.Confidence, Outdated: d.Evidence["outdated"]}
		for k, v := range d.Evidence {
			dv.Evidence = append(dv.Evidence, KV{k, v})
		}
		sort.Slice(dv.Evidence, func(i, j int) bool { return dv.Evidence[i].K < dv.Evidence[j].K })
		if !d.Meta.Empty() {
			dv.CWE, dv.Attack, dv.Remediation = d.Meta.CWE, d.Meta.Attack, d.Meta.Remediation
		}
		p.Detections = append(p.Detections, dv)
	}
	if sv.HTTP != nil {
		obs, err := s.d.Store.HTTPObs(ctx, sv.ID)
		switch {
		case errors.Is(err, store.ErrNotFound):
		case err != nil:
			return p, fmt.Errorf("http observation: %w", err)
		default:
			p.HTTP = &obs
			p.Slow = obs.ResponseMS >= slowResponseMS
			names := make([]string, 0, len(obs.Headers))
			for n := range obs.Headers {
				names = append(names, n)
			}
			sort.Strings(names)
			for _, n := range names {
				p.Headers = append(p.Headers, HeaderRow{Name: n, Values: obs.Headers[n]})
			}
		}
	}
	hist, err := s.d.Store.AssetHistory(ctx, key, availabilityRuns)
	if err != nil {
		return p, fmt.Errorf("history: %w", err)
	}
	p.Avail = availView(hist.Runs)
	p.Changes = changeRows(hist.Changes)
	p.Note, err = s.annotationFor(ctx, key, form)
	return p, err
}
