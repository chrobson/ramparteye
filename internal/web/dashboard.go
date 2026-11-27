package web

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/chrobson/ramparteye/internal/auth"
	"github.com/chrobson/ramparteye/internal/interest"
	"github.com/chrobson/ramparteye/internal/model"
	"github.com/chrobson/ramparteye/internal/store"
	"github.com/chrobson/ramparteye/internal/summary"
	"github.com/chrobson/ramparteye/internal/target"
)

// Dashboard list sizes and thresholds.
const maxAddrsShown = 1e15 // display cap of the address count

const (
	reviewMin      = 30                // interest score from which a service is listed
	urgentMin      = summary.UrgentMin // "high" priority: needs attention now
	reviewListLen  = 5
	changesListLen = 6
	runsLookback   = 10
)

// DashboardData is everything shown on "/". Headline and Sub are filled
// from the counts by Headline.
type DashboardData struct {
	Title string

	HasRuns    bool // any run exists
	HasDoneRun bool // a run has finished, so the counts below mean something
	Running    bool // a scan is running now
	Headline   string
	Sub        string
	LastScan   string // "Scan #6 finished 12 min ago." ("" when unknown)

	// Changes of the latest finished run against its predecessor.
	NewHosts, HostsGone, NewServices, ServicesGone, Changed, Unstable int
	Urgent                                                            int // services of high priority

	AddrsInScope int
	ActiveHosts  int
	OpenServices int
	WebServices  int
	Findings     int
	AdminPanels  int

	Review      []ServiceItem
	Interesting []ServiceItem
	Changes     []ChangeItem

	Categories BarChart
	HostStates BarChart

	Live []LiveRun
}

// ServiceItem is a service in a dashboard list.
type ServiceItem struct {
	Name     string // first detection, else product or service
	Endpoint string // ip:port
	Detail   string // category or note
	Severity model.Severity
	Score    int
}

// ChangeItem is a change in the "Latest changes" list.
type ChangeItem struct {
	Kind     model.ChangeKind
	Endpoint string
	Detail   string
	RunID    int64
}

// LiveRun is a run in the live scan panel.
type LiveRun struct {
	RunID    int64
	Name     string // scan profile; may be empty
	Percent  int    // 0-100
	PPS      int
	PPSPct   int // PPS against the run budget, 0-100
	Budget   int // safety policy limit in packets/s
	Finished bool
	Status   string // final status of a finished run
}

// Headline returns the dashboard headline and its sub line. Counts of zero
// are left out; the sub line says whether anything needs urgent attention
// and when the last scan finished.
func Headline(d DashboardData) (title, sub string) {
	switch {
	case !d.HasRuns:
		return "No scans yet.", "Create a scan profile and start the first scan; results appear here."
	case !d.HasDoneRun && d.Running:
		return "First scan in progress.", "Results appear here when it finishes."
	case !d.HasDoneRun:
		return "No finished scans yet.", "Results appear here when a scan finishes."
	}
	title, sub = summary.Headline(summary.Counts{NewHosts: d.NewHosts, HostsGone: d.HostsGone,
		NewServices: d.NewServices, ServicesGone: d.ServicesGone, Changed: d.Changed, Unstable: d.Unstable}, d.Urgent)
	if d.LastScan != "" {
		sub += " " + d.LastScan
	}
	return title, sub
}

func plural(n int, one, many string) string { return summary.Plural(n, one, many) }

func (s *Server) dashboard(w http.ResponseWriter, r *http.Request) {
	d, err := s.loadDashboard(r.Context())
	if err != nil {
		s.log.Error("load dashboard", "err", err)
		s.serverError(w, r)
		return
	}
	s.render(w, r, "dashboard", d)
}

// loadDashboard gathers the numbers of the newest finished run. A failing
// store query fails the page: a dashboard with silently missing parts would
// mislead.
func (s *Server) loadDashboard(ctx context.Context) (DashboardData, error) {
	d := DashboardData{Title: "Dashboard"}
	st := s.d.Store

	targets, err := st.Targets(ctx, "")
	if err != nil {
		return d, fmt.Errorf("targets: %w", err)
	}
	var total uint64
	for _, t := range targets {
		total = satAdd(total, targetAddrs(t))
	}
	d.AddrsInScope = int(min(total, maxAddrsShown))
	runs, err := st.Runs(ctx, runsLookback)
	if err != nil {
		return d, fmt.Errorf("runs: %w", err)
	}
	d.Live = s.liveSeed(runs)
	runID, err := st.LatestDoneRun(ctx)
	if err != nil {
		return d, fmt.Errorf("latest run: %w", err)
	}
	d.HasRuns = len(runs) > 0
	d.Running = len(d.Live) > 0
	d.HasDoneRun = runID != 0
	if runID != 0 {
		if err := s.loadRunPart(ctx, &d, runID); err != nil {
			return d, err
		}
	}
	counts, err := st.HostStateCounts(ctx)
	if err != nil {
		return d, fmt.Errorf("host state counts: %w", err)
	}
	d.HostStates = hostStateChart(counts)
	d.Headline, d.Sub = Headline(d)
	return d, nil
}

func (s *Server) loadRunPart(ctx context.Context, d *DashboardData, runID int64) error {
	st := s.d.Store
	last, err := st.Run(ctx, runID)
	if err != nil {
		return fmt.Errorf("latest run: %w", err)
	}
	if last.FinishedAt != nil {
		d.LastScan = fmt.Sprintf("Scan #%d finished %s.", last.ID, agoFunc(s.now)(*last.FinishedAt))
	}
	changes, err := st.Changes(ctx, runID)
	if err != nil {
		return fmt.Errorf("changes: %w", err)
	}
	c := summary.CountChanges(changes)
	d.NewHosts, d.HostsGone, d.NewServices, d.ServicesGone, d.Changed, d.Unstable =
		c.NewHosts, c.HostsGone, c.NewServices, c.ServicesGone, c.Changed, c.Unstable
	for i, c := range changes {
		if i == changesListLen {
			break
		}
		d.Changes = append(d.Changes, ChangeItem{Kind: c.Kind, Endpoint: endpoint(c.Key), RunID: c.RunID,
			Detail: changeDetail(c)})
	}

	hosts, err := st.RunHostObs(ctx, runID)
	if err != nil {
		return fmt.Errorf("host observations: %w", err)
	}
	var ips []netip.Addr
	for _, h := range hosts {
		if h.Up {
			d.ActiveHosts++
		}
	}
	svcs, err := st.ExportServices(ctx, runID)
	if err != nil {
		return fmt.Errorf("services: %w", err)
	}
	d.OpenServices = len(svcs)
	seen := map[netip.Addr]bool{}
	cats := map[string]int{}
	for _, sv := range svcs {
		if sv.HTTP != nil {
			d.WebServices++
		}
		for _, det := range sv.Detections {
			d.Findings++
			cats[det.Category]++
			if det.Category == "admin-panel" {
				d.AdminPanels++
			}
		}
		if ip := sv.Key.IP; !seen[ip] {
			seen[ip] = true
			ips = append(ips, ip)
		}
	}
	d.Categories = categoryChart(cats)

	unstable, err := st.HostStates(ctx, model.HostUnstable)
	if err != nil {
		return fmt.Errorf("unstable hosts: %w", err)
	}
	unstableSet := map[netip.Addr]bool{}
	for _, h := range unstable {
		unstableSet[h.IP.Unmap()] = true
	}
	notes, err := st.AnnotationsByIPs(ctx, ips)
	if err != nil {
		return fmt.Errorf("annotations: %w", err)
	}
	// Ranked highest score first, so both lists come out in score order.
	for _, rk := range summary.Rank(svcs, summary.ChangeKinds(changes), unstableSet, notes) {
		it := serviceItem(rk.Service, rk.Score)
		if rk.Score >= urgentMin {
			d.Urgent++
		}
		if rk.Score >= reviewMin && len(d.Review) < reviewListLen {
			d.Review = append(d.Review, it)
		}
		for _, det := range rk.Service.Detections {
			if det.Category == "admin-panel" || det.Category == "staging" {
				n := it
				n.Name, n.Detail = det.Name, strings.ReplaceAll(det.Category, "-", " ")
				d.Interesting = append(d.Interesting, n)
				break
			}
		}
	}
	if len(d.Interesting) > reviewListLen {
		d.Interesting = d.Interesting[:reviewListLen]
	}
	return nil
}

// interestInput maps a stored service to the scoring input (see
// summary.InterestInput).
func interestInput(sv store.ExportService, kinds []string, unstable bool, note store.Annotation) interest.Input {
	return summary.InterestInput(sv, kinds, unstable, note)
}

var severityRank = map[model.Severity]int{model.SevInfo: 0, model.SevLow: 1, model.SevMedium: 2,
	model.SevHigh: 3, model.SevCritical: 4}

func serviceItem(sv store.ExportService, score int) ServiceItem {
	it := ServiceItem{Endpoint: endpoint(sv.Key), Score: score, Severity: model.SevInfo,
		Name: strings.TrimSpace(sv.Product), Detail: sv.Banner}
	if i, sev := summary.Strongest(sv.Detections); i >= 0 {
		d := sv.Detections[i]
		it.Severity, it.Name, it.Detail = sev, d.Name, strings.ReplaceAll(d.Category, "-", " ")
	}
	if it.Name == "" {
		it.Name = sv.Banner
	}
	return it
}

func endpoint(k model.AssetKey) string {
	if !k.IP.IsValid() {
		return ""
	}
	if k.Port == 0 {
		return k.IP.String()
	}
	return netip.AddrPortFrom(k.IP, k.Port).String()
}

func changeDetail(c model.Change) string {
	switch {
	case c.Field != "" && (c.Old != "" || c.New != ""):
		return c.Field + ": " + c.Old + " → " + c.New
	case c.Field != "":
		return c.Field
	}
	return ""
}

// satAdd adds with saturation.
func satAdd(a, b uint64) uint64 {
	if s := a + b; s >= a {
		return s
	}
	return ^uint64(0)
}

// targetAddrs counts the addresses a target stands for.
func targetAddrs(t model.Target) uint64 {
	switch t.Kind {
	case model.TargetCIDR:
		if p, err := netip.ParsePrefix(t.Value); err == nil {
			return target.AddrCount(p)
		}
	case model.TargetRange:
		lo, hi, ok := strings.Cut(t.Value, "-")
		a, err1 := netip.ParseAddr(strings.TrimSpace(lo))
		b, err2 := netip.ParseAddr(strings.TrimSpace(hi))
		if ok && err1 == nil && err2 == nil && a.Is4() && b.Is4() && a.Compare(b) <= 0 {
			return uint64(addr4(b)) - uint64(addr4(a)) + 1
		}
	}
	return 1
}

func addr4(a netip.Addr) uint32 {
	b := a.As4()
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

// liveSeed lists the runs the runner reports active, with name and a
// progress estimate from chunk counts, for the initial live panel.
func (s *Server) liveSeed(runs []store.RunSummary) []LiveRun {
	if s.d.Runner == nil {
		return nil
	}
	byID := map[int64]store.RunSummary{}
	for _, r := range runs {
		byID[r.ID] = r
	}
	var out []LiveRun
	for _, id := range s.d.Runner.ActiveRuns() {
		lr := LiveRun{RunID: id, Budget: s.d.Cfg.MaxRate}
		if r, ok := byID[id]; ok {
			lr.Name = r.ConfigName
			if r.ChunksTotal > 0 {
				lr.Percent = r.ChunksDone * 90 / r.ChunksTotal
			}
		}
		out = append(out, lr)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].RunID < out[j].RunID })
	return out
}

// cancelAll stops every unfinished scan and redirects back with a flash.
func (s *Server) cancelAll(w http.ResponseWriter, r *http.Request) {
	u, _ := auth.CurrentUser(r.Context())
	msg := "No scan runner is available."
	if s.d.Runner != nil {
		ids, err := s.d.Runner.CancelAll(r.Context(), u.ID)
		switch {
		case err != nil:
			s.log.Error("cancel all scans", "err", err)
			msg = "Cancelling scans failed; see the server log."
		case len(ids) == 0:
			msg = "No scans were running or queued."
		default:
			refs := make([]string, len(ids))
			for i, id := range ids {
				refs[i] = "#" + strconv.FormatInt(id, 10)
			}
			msg = "Cancel requested for " + plural(len(ids), "run", "runs") + ": " + strings.Join(refs, ", ") + "."
		}
	}
	setFlash(w, r, msg)
	http.Redirect(w, r, backPath(r), http.StatusSeeOther)
}

// backPath is the local path of the Referer, or "/".
func backPath(r *http.Request) string {
	ref, err := url.Parse(r.Referer())
	if err != nil || (ref.Host != "" && ref.Host != r.Host) {
		return "/"
	}
	p := ref.EscapedPath()
	if ref.RawQuery != "" {
		p += "?" + ref.RawQuery
	}
	return safeNext(p)
}

const (
	flashCookie = "rampart_flash"
	maxFlash    = 400
)

// setFlash stores a one-time message for the next page.
func setFlash(w http.ResponseWriter, r *http.Request, msg string) {
	if len(msg) > maxFlash {
		msg = msg[:maxFlash]
	}
	http.SetCookie(w, &http.Cookie{Name: flashCookie, Value: url.QueryEscape(msg), Path: "/",
		MaxAge: 60, HttpOnly: true, Secure: auth.IsTLS(r), SameSite: http.SameSiteLaxMode})
}

// takeFlash returns and clears the flash message.
func takeFlash(w http.ResponseWriter, r *http.Request) string {
	c, err := r.Cookie(flashCookie)
	if err != nil {
		return ""
	}
	http.SetCookie(w, &http.Cookie{Name: flashCookie, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: auth.IsTLS(r), SameSite: http.SameSiteLaxMode})
	msg, err := url.QueryUnescape(c.Value)
	if err != nil || len(msg) > maxFlash {
		return ""
	}
	return strings.ToValidUTF8(msg, "�")
}
