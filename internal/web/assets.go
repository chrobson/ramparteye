package web

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/chrobson/ramparteye/internal/dojo"
	"github.com/chrobson/ramparteye/internal/interest"
	"github.com/chrobson/ramparteye/internal/model"
	"github.com/chrobson/ramparteye/internal/sig"
	"github.com/chrobson/ramparteye/internal/store"
)

// Limits of the asset pages.
const (
	maxFilterText    = 200 // bytes of the text filter
	assetsLimit      = 500 // rows shown on the list
	availabilityRuns = 30  // finished scans the host and service history looks back over
)

// Quick filters of the asset list.
const (
	quickAdmin   = "admin"
	quickDB      = "db"
	quickStaging = "staging"
	quickIoT     = "iot"
	quickNew     = "new"
)

// QuickFilter is one quick filter chip.
type QuickFilter struct {
	Key, Label string
}

var quickFilters = []QuickFilter{
	{quickAdmin, "Admin panels"},
	{quickDB, "Exposed DB"},
	{quickStaging, "Staging"},
	{quickIoT, "IoT"},
	{quickNew, "New since last scan"},
}

var hostStateFilters = []model.HostStateKind{model.HostUp, model.HostDown, model.HostInactive, model.HostUnstable}

// errBadFilter marks an invalid query parameter of the asset list.
var errBadFilter = errors.New("invalid filter")

// assetFilter is the validated query of the asset list.
type assetFilter struct {
	State model.HostStateKind // "" = any
	Min   int                 // minimum interest score
	Text  string              // case-insensitive substring
	Quick string
}

// parseAssetFilter validates the query: state, min (0-100), q and quick.
func parseAssetFilter(q url.Values) (assetFilter, error) {
	var f assetFilter
	if v := q.Get("state"); v != "" {
		ok := false
		for _, k := range hostStateFilters {
			ok = ok || string(k) == v
		}
		if !ok {
			return f, fmt.Errorf("%w: unknown state", errBadFilter)
		}
		f.State = model.HostStateKind(v)
	}
	if v := q.Get("min"); v != "" {
		n, err := strconv.ParseUint(v, 10, 8)
		if err != nil || n > 100 {
			return f, fmt.Errorf("%w: min must be 0-100", errBadFilter)
		}
		f.Min = int(n)
	}
	f.Text = strings.TrimSpace(q.Get("q"))
	if len(f.Text) > maxFilterText || !utf8.ValidString(f.Text) {
		return f, fmt.Errorf("%w: text too long", errBadFilter)
	}
	if v := q.Get("quick"); v != "" {
		ok := false
		for _, k := range quickFilters {
			ok = ok || k.Key == v
		}
		if !ok {
			return f, fmt.Errorf("%w: unknown quick filter", errBadFilter)
		}
		f.Quick = v
	}
	return f, nil
}

// AssetsData is the asset list page and its table fragment.
type AssetsData struct {
	Title    string
	Filter   assetFilter
	Quick    []QuickFilter
	States   []model.HostStateKind
	Rows     []AssetRow
	Total    int // rows matching the filter, before the display limit
	Limit    int
	HasRun   bool
	Filtered bool
	Error    string // inline message for an invalid filter (htmx requests)
	// The time machine: AsOf is set when the list shows a past run; Picker
	// offers the recent finished runs, Keep the filters it carries along.
	AsOf   *AsOf
	Picker []RunOption
	Keep   []KV
}

// AssetRow is a host on the asset list.
type AssetRow struct {
	IP         string
	Href       string
	Hostname   string
	State      model.HostStateKind
	StateClass string
	Services   int
	Score      int
	Top        string // the highest scoring service
	TopSev     model.Severity
	LastSeen   time.Time
	Noted      bool
}

// scoredService is a service of the latest run with its interest score.
type scoredService struct {
	store.ExportService
	Result interest.Result
	Sev    model.Severity // highest detection severity
	Item   ServiceItem
}

// snapshot is the state of the latest finished run that the asset pages
// are built from.
type snapshot struct {
	RunID     int64
	States    []model.HostState
	Hostnames map[netip.Addr]string
	Services  map[netip.Addr][]scoredService
	NewHosts  map[netip.Addr]bool // new service or host back in the latest run
	Notes     map[model.AssetKey]store.Annotation
	Noted     map[netip.Addr]bool // hosts with any annotation
}

// loadSnapshot gathers hosts, the services of the latest finished run with
// their scores, and the notes. A failing query fails the page.
func (s *Server) loadSnapshot(ctx context.Context) (snapshot, error) {
	st := s.d.Store
	snap := newSnapshot()
	var err error
	if snap.States, err = st.HostStates(ctx, ""); err != nil {
		return snap, fmt.Errorf("host states: %w", err)
	}
	if snap.RunID, err = st.LatestDoneRun(ctx); err != nil {
		return snap, fmt.Errorf("latest run: %w", err)
	}
	unstable := map[netip.Addr]bool{}
	for _, h := range snap.States {
		unstable[h.IP.Unmap()] = h.State == model.HostUnstable
	}
	if err := s.loadNotes(ctx, &snap); err != nil {
		return snap, err
	}
	if snap.RunID == 0 {
		return snap, nil
	}
	changes, hosts, svcs, err := s.loadRunObs(ctx, snap.RunID)
	if err != nil {
		return snap, err
	}
	snap.addRun(changes, hosts, svcs, unstable)
	return snap, nil
}

func newSnapshot() snapshot {
	return snapshot{Hostnames: map[netip.Addr]string{}, Services: map[netip.Addr][]scoredService{},
		NewHosts: map[netip.Addr]bool{}}
}

// loadNotes loads the annotations of the snapshot's hosts.
func (s *Server) loadNotes(ctx context.Context, snap *snapshot) error {
	ips := make([]netip.Addr, 0, len(snap.States))
	for _, h := range snap.States {
		ips = append(ips, h.IP.Unmap())
	}
	var err error
	if snap.Notes, err = s.d.Store.AnnotationsByIPs(ctx, ips); err != nil {
		return fmt.Errorf("annotations: %w", err)
	}
	snap.Noted = map[netip.Addr]bool{}
	for k := range snap.Notes {
		snap.Noted[k.IP.Unmap()] = true
	}
	return nil
}

// loadRunObs loads the changes, host observations and services of a run.
func (s *Server) loadRunObs(ctx context.Context, runID int64) ([]model.Change, []model.HostObs, []store.ExportService, error) {
	st := s.d.Store
	changes, err := st.Changes(ctx, runID)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("changes: %w", err)
	}
	hosts, err := st.RunHostObs(ctx, runID)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("host observations: %w", err)
	}
	svcs, err := st.ExportServices(ctx, runID)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("services: %w", err)
	}
	return changes, hosts, svcs, nil
}

// addRun adds the host names and the scored services of a run; unstable
// marks the hosts that count as unstable in the score. Notes must be loaded.
func (snap *snapshot) addRun(changes []model.Change, hosts []model.HostObs, svcs []store.ExportService,
	unstable map[netip.Addr]bool) {
	kinds := map[model.AssetKey][]string{}
	for _, c := range changes {
		kinds[c.Key] = append(kinds[c.Key], string(c.Kind))
		if c.Kind == model.ChangeNew || c.Kind == model.ChangeHostUp {
			snap.NewHosts[c.Key.IP.Unmap()] = true
		}
	}
	for _, h := range hosts {
		if h.Hostname != "" {
			snap.Hostnames[h.IP.Unmap()] = h.Hostname
		}
	}
	for _, sv := range svcs {
		ip := sv.Key.IP.Unmap()
		res := interest.Score(interestInput(sv, kinds[sv.Key], unstable[ip], snap.Notes[sv.Key]))
		item := serviceItem(sv, res.Score)
		snap.Services[ip] = append(snap.Services[ip], scoredService{ExportService: sv, Result: res,
			Sev: item.Severity, Item: item})
		if sv.Hostname != "" && snap.Hostnames[ip] == "" {
			snap.Hostnames[ip] = sv.Hostname
		}
	}
}

// hostMatches reports whether a host passes the filter.
func (snap snapshot) hostMatches(h model.HostState, f assetFilter) bool {
	ip := h.IP.Unmap()
	svcs := snap.Services[ip]
	if f.State != "" && h.State != f.State {
		return false
	}
	if f.Min > 0 && maxScore(svcs) < f.Min {
		return false
	}
	if f.Quick != "" && !snap.quickMatch(ip, svcs, f.Quick) {
		return false
	}
	if f.Text == "" {
		return true
	}
	needle := strings.ToLower(f.Text)
	has := func(v string) bool { return strings.Contains(strings.ToLower(v), needle) }
	if has(ip.String()) || has(snap.Hostnames[ip]) {
		return true
	}
	for _, sv := range svcs {
		if has(sv.Product) || has(sv.Banner) || has(sv.Version) {
			return true
		}
		for _, d := range sv.Detections {
			if has(d.Name) || has(d.SignatureID) {
				return true
			}
		}
	}
	return false
}

func (snap snapshot) quickMatch(ip netip.Addr, svcs []scoredService, quick string) bool {
	if quick == quickNew {
		return snap.NewHosts[ip]
	}
	for _, sv := range svcs {
		if quick == quickDB && interest.ExposedDatabase(sv.Banner, int(sv.Key.Port)) {
			return true
		}
		for _, d := range sv.Detections {
			if (quick == quickAdmin && d.Category == "admin-panel") ||
				(quick == quickStaging && d.Category == "staging") ||
				(quick == quickIoT && d.Category == "iot") {
				return true
			}
		}
	}
	return false
}

func maxScore(svcs []scoredService) int {
	m := 0
	for _, sv := range svcs {
		m = max(m, sv.Result.Score)
	}
	return m
}

// assetRows builds the filtered, sorted list rows; host links are as of
// run (0 = the latest view).
func (snap snapshot) assetRows(f assetFilter, run int64) (rows []AssetRow, total int) {
	for _, h := range snap.States {
		if !snap.hostMatches(h, f) {
			continue
		}
		ip := h.IP.Unmap()
		row := AssetRow{IP: ip.String(), Href: assetPathAt(model.AssetKey{IP: ip}, run), Hostname: snap.Hostnames[ip],
			State: h.State, StateClass: stateClass(h.State), LastSeen: h.LastSeen, Services: len(snap.Services[ip])}
		for _, sv := range snap.Services[ip] {
			if sv.Result.Score >= row.Score && (row.Top == "" || sv.Result.Score > row.Score) {
				row.Score, row.Top, row.TopSev = sv.Result.Score, sv.Item.Name, sv.Sev
			}
		}
		row.Noted = snap.Noted[ip]
		rows = append(rows, row)
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].Score != rows[j].Score {
			return rows[i].Score > rows[j].Score
		}
		return netip.MustParseAddr(rows[i].IP).Less(netip.MustParseAddr(rows[j].IP))
	})
	total = len(rows)
	if len(rows) > assetsLimit {
		rows = rows[:assetsLimit]
	}
	return rows, total
}

func stateClass(k model.HostStateKind) string {
	switch k {
	case model.HostUp:
		return "tag-up"
	case model.HostUnstable:
		return "tag-flap"
	default:
		return "tag-gone"
	}
}

func (s *Server) assetsList(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Vary", "HX-Request")
	f, err := parseAssetFilter(r.URL.Query())
	htmx := r.Header.Get("HX-Request") == "true" && r.Header.Get("HX-History-Restore-Request") == ""
	var asOf *AsOf
	if err == nil {
		asOf, err = s.requestAsOf(r, func(run int64) string { return assetsPathAt(f.values(), run) })
	}
	if err == nil && asOf != nil && f.State != "" && f.State != model.HostUp && f.State != model.HostDown {
		err = fmt.Errorf("%w: a past run tells only whether a host answered (up or down)", errBadFilter)
	}
	var re *runError
	switch {
	case err != nil && htmx && (errors.Is(err, errBadFilter) || errors.As(err, &re)):
		msg := "Invalid filter: " + strings.TrimPrefix(err.Error(), errBadFilter.Error()+": ") + "."
		if re != nil {
			msg = re.text
		}
		s.renderFragment(w, r, "assets", "assets-results", AssetsData{Error: msg,
			Quick: quickFilters, States: hostStateFilters, Limit: assetsLimit})
		return
	case errors.Is(err, errBadFilter):
		s.renderError(w, r, errorData{Code: http.StatusBadRequest, Title: "Invalid filter",
			Text: "One of the filters is not valid. Clear the filters and try again."})
		return
	case err != nil:
		s.runErrorPage(w, r, err)
		return
	}
	snap, err := s.snapshotAsOf(r.Context(), asOf)
	if err != nil {
		s.log.Error("load assets", "err", err)
		s.serverError(w, r)
		return
	}
	d := AssetsData{Title: "Assets", Filter: f, Quick: quickFilters, States: hostStateFilters,
		HasRun: snap.RunID != 0, Limit: assetsLimit,
		Filtered: f != assetFilter{}, AsOf: asOf}
	if asOf != nil {
		d.States = runStateFilters
	}
	d.Rows, d.Total = snap.assetRows(f, asOf.run())
	if htmx {
		s.renderFragment(w, r, "assets", "assets-results", d)
		return
	}
	if d.Picker, err = s.runPicker(r.Context(), asOf); err != nil {
		s.log.Error("load assets", "err", err)
		s.serverError(w, r)
		return
	}
	// The picker carries the filters along, except a state a past run cannot tell.
	keep := f.values()
	if !slices.Contains(runStateFilters, f.State) {
		keep.Del("state")
	}
	for _, k := range []string{"q", "state", "min", "quick"} {
		if v := keep.Get(k); v != "" {
			d.Keep = append(d.Keep, KV{k, v})
		}
	}
	s.render(w, r, "assets", d)
}

// renderFragment writes one named template of a page without the layout,
// for htmx partial swaps.
func (s *Server) renderFragment(w http.ResponseWriter, r *http.Request, page, name string, data any) {
	t, ok := s.pages.set[page]
	if !ok {
		s.log.Error("render fragment", "page", page, "err", "unknown page")
		s.serverError(w, r)
		return
	}
	var buf bytes.Buffer
	if err := t.ExecuteTemplate(&buf, name, View{Ctx: r.Context(), Data: data}); err != nil {
		s.log.Error("render fragment", "page", page, "fragment", name, "err", err)
		s.serverError(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = buf.WriteTo(w)
}

// Path parameter validation. Anything invalid is simply "not found": the
// parameter is never echoed.

var protos = map[string]bool{"tcp": true, "udp": true, "sctp": true}

// parseIP accepts a plain IP address; IPv4-mapped addresses are unmapped
// and zones are refused.
func parseIP(s string) (netip.Addr, bool) {
	a, err := netip.ParseAddr(s)
	if err != nil || a.Zone() != "" {
		return netip.Addr{}, false
	}
	return a.Unmap(), true
}

// parsePort accepts decimal digits only, 1-65535.
func parsePort(s string) (uint16, bool) {
	n, err := strconv.ParseUint(s, 10, 16)
	if err != nil || n == 0 {
		return 0, false
	}
	return uint16(n), true
}

// assetPath returns the page URL of a key (host page for port 0).
func assetPath(k model.AssetKey) string {
	u := url.URL{Path: "/assets/" + k.IP.Unmap().String()}
	if k.Port != 0 {
		u.Path += "/" + strconv.Itoa(int(k.Port)) + "/" + k.Proto
		if k.VHost != "" {
			u.RawQuery = url.Values{"vhost": {k.VHost}}.Encode()
		}
	}
	return u.String()
}

// detectionIDs lists signature ids of services for metadata lookup.
func detectionIDs(svcs []scoredService) map[string]bool {
	ids := map[string]bool{}
	for _, sv := range svcs {
		for _, d := range sv.Detections {
			ids[d.SignatureID] = true
		}
	}
	return ids
}

// attachMeta sets Detection.Meta of the services from the current
// signatures. Only signatures in ids are parsed.
func (s *Server) attachMeta(ctx context.Context, svcs []scoredService, ids map[string]bool) error {
	if len(ids) == 0 {
		return nil
	}
	rows, err := s.d.Store.Signatures(ctx)
	if err != nil {
		return fmt.Errorf("signatures: %w", err)
	}
	metas := map[string]model.SignatureMeta{}
	for _, row := range rows {
		if !ids[row.ID] {
			continue
		}
		sg, err := sig.Parse([]byte(row.YAML))
		if err != nil {
			continue // a broken signature has no metadata; the detection still shows
		}
		if m := sg.Meta(); m != nil {
			metas[row.ID] = *m
		}
	}
	for i := range svcs {
		model.AttachMeta(svcs[i].Detections, metas)
	}
	return nil
}

// reasonView is one row of a score breakdown.
type ReasonView struct {
	Rule   string
	Points int // 0 = the rule has no points of its own
}

func reasonViews(res interest.Result) []ReasonView {
	out := make([]ReasonView, len(res.Reasons))
	for i, r := range res.Reasons {
		out[i] = ReasonView{Rule: r.Rule, Points: r.Points}
	}
	return out
}

// DetectionBadge is a detection as a severity badge.
type DetectionBadge struct {
	Name     string
	Severity model.Severity
}

func detectionBadges(ds []model.Detection) []DetectionBadge {
	out := make([]DetectionBadge, len(ds))
	for i, d := range ds {
		out[i] = DetectionBadge{Name: d.Name, Severity: dojo.DetectionSeverity(d)}
	}
	return out
}
