package web

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/chrobson/ramparteye/internal/auth"
	"github.com/chrobson/ramparteye/internal/dojo"
)

// Shell is the layout data: user, top bar chips, safety strip and the
// sidebar navigation.
type Shell struct {
	User     string
	Role     string
	ScanChip Chip
	DojoChip Chip
	Safety   Safety
	Nav      []NavGroup
}

// Chip is a top bar status chip. Kind is chip-ok, chip-bad or chip-off.
type Chip struct {
	Text string
	Kind string
	Href string
}

// Safety is the safety strip: the active scope, the packet rate limit and
// the HTTP methods signatures may send.
type Safety struct {
	Scope    string // summary; empty = no scope (every scan refused)
	ScopeAll string // every allowed prefix, for the tooltip
	PPS      int
	Methods  string
}

// NavGroup is a titled group of sidebar links.
type NavGroup struct {
	Label string
	Items []NavItem
}

// NavItem is a sidebar link shown to users holding Perm.
type NavItem struct {
	Label  string
	Href   string
	Perm   auth.Perm
	Active bool
}

// navGroups is the sidebar (design 6.2a).
var navGroups = []NavGroup{
	{Label: "Observe", Items: []NavItem{
		{Label: "Dashboard", Href: "/", Perm: auth.PermResultsRead},
		{Label: "Scans", Href: "/scans", Perm: auth.PermResultsRead},
		{Label: "Assets", Href: "/assets", Perm: auth.PermResultsRead},
		{Label: "Changes", Href: "/changes", Perm: auth.PermResultsRead},
		{Label: "Findings", Href: "/findings", Perm: auth.PermResultsRead},
	}},
	{Label: "Configure", Items: []NavItem{
		{Label: "Signatures", Href: "/signatures", Perm: auth.PermResultsRead},
		{Label: "Scan profiles", Href: "/profiles", Perm: auth.PermTargetsRead},
		{Label: "Import / export", Href: "/exchange", Perm: auth.PermExport},
		{Label: "Settings", Href: "/settings", Perm: auth.PermSettingsAdmin},
	}},
}

// navItems is navGroups flattened.
var navItems = func() []NavItem {
	var out []NavItem
	for _, g := range navGroups {
		out = append(out, g.Items...)
	}
	return out
}()

// buildNav returns the groups with the items the user may open and the
// current section marked active.
func buildNav(r *http.Request) []NavGroup {
	var out []NavGroup
	for _, g := range navGroups {
		ng := NavGroup{Label: g.Label}
		for _, it := range g.Items {
			if !auth.Can(r.Context(), it.Perm) {
				continue
			}
			it.Active = isSection(r.URL.Path, it.Href)
			ng.Items = append(ng.Items, it)
		}
		if len(ng.Items) > 0 {
			out = append(out, ng)
		}
	}
	return out
}

func isSection(path, href string) bool {
	if href == "/" {
		return path == "/"
	}
	return path == href || strings.HasPrefix(path, href+"/")
}

// shell builds the layout data. Chip failures degrade to an
// "unavailable" chip; they never fail the page.
func (s *Server) shell(r *http.Request, u auth.User) Shell {
	allowed := s.d.Scope.Allowed()
	prefixes := make([]string, len(allowed))
	for i, p := range allowed {
		prefixes[i] = p.String()
	}
	sh := Shell{
		User: u.Login,
		Role: u.RoleName,
		Safety: Safety{
			Scope:    scopeSummary(prefixes),
			ScopeAll: strings.Join(prefixes, ", "),
			PPS:      s.d.Cfg.MaxRate,
			Methods:  "GET/HEAD",
		},
		Nav: buildNav(r),
	}
	var active []int64
	if s.d.Runner != nil {
		active = s.d.Runner.ActiveRuns()
	}
	sh.ScanChip = scanChip(active)
	var (
		state dojo.ChipState
		err   error
	)
	if s.d.Pusher != nil {
		if state, err = s.d.Pusher.Status(r.Context()); err != nil {
			s.log.Warn("DefectDojo chip status", "err", err)
		}
	}
	sh.DojoChip = dojoChip(state, err, agoFunc(s.now))
	if auth.Can(r.Context(), auth.PermSettingsAdmin) {
		sh.DojoChip.Href = "/settings"
	}
	return sh
}

// scopeSummary lists at most two prefixes and counts the rest.
func scopeSummary(prefixes []string) string {
	if len(prefixes) <= 2 {
		return strings.Join(prefixes, ", ")
	}
	return strings.Join(prefixes[:2], ", ") + " +" + strconv.Itoa(len(prefixes)-2) + " more"
}

func scanChip(active []int64) Chip {
	c := Chip{Kind: "chip-off", Text: "No scan running", Href: "/scans"}
	switch len(active) {
	case 0:
	case 1:
		c.Kind, c.Text = "chip-ok", "Scan #"+strconv.FormatInt(active[0], 10)+" running"
	default:
		c.Kind, c.Text = "chip-ok", strconv.Itoa(len(active))+" scans running"
	}
	return c
}

func dojoChip(st dojo.ChipState, err error, ago func(time.Time) string) Chip {
	const p = "DefectDojo · "
	switch {
	case err != nil:
		return Chip{Kind: "chip-bad", Text: p + "status unavailable"}
	case !st.Configured:
		return Chip{Kind: "chip-off", Text: p + "not configured"}
	case st.LastOK == nil:
		return Chip{Kind: "chip-off", Text: p + "no pushes yet"}
	case !*st.LastOK:
		return Chip{Kind: "chip-bad", Text: p + "last push failed"}
	default:
		return Chip{Kind: "chip-ok", Text: p + num(st.Findings) + " findings · synced " + ago(st.LastAt)}
	}
}
