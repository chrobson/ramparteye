package web

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/chrobson/ramparteye/internal/auth"
	"github.com/chrobson/ramparteye/internal/dojo"
	"github.com/chrobson/ramparteye/internal/store"
)

// Settings page limits.
const (
	pushHistoryRows = 20
	auditPageSize   = 50
	maxAuditPage    = 10000
)

// SettingsTab is a tab of the settings pages.
type SettingsTab struct {
	Label  string
	Href   string
	Perm   auth.Perm
	Active bool
}

var settingsTabs = []SettingsTab{
	{Label: "Scope", Href: "/settings/scope", Perm: auth.PermSettingsAdmin},
	{Label: "Users & roles", Href: "/settings/users", Perm: auth.PermUsersAdmin},
	{Label: "Integrations", Href: "/settings/integrations", Perm: auth.PermSettingsAdmin},
	{Label: "Audit log", Href: "/settings/audit", Perm: auth.PermSettingsAdmin},
}

// tabs returns the settings tabs the user may open, active one marked.
func tabs(r *http.Request, active string) []SettingsTab {
	var out []SettingsTab
	for _, t := range settingsTabs {
		if auth.Can(r.Context(), t.Perm) {
			t.Active = t.Href == active
			out = append(out, t)
		}
	}
	return out
}

// ScopeData is the read-only Scope tab.
type ScopeData struct {
	Tabs     []SettingsTab
	Allowed  []string
	Excluded []string
	Ports    string
	MaxRate  int
	Methods  string
	Proxies  []string
}

func (s *Server) settingsIndex(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/settings/scope", http.StatusSeeOther)
}

func (s *Server) settingsScope(w http.ResponseWriter, r *http.Request) {
	d := ScopeData{Tabs: tabs(r, "/settings/scope"), MaxRate: s.d.Cfg.MaxRate, Methods: "GET/HEAD"}
	for _, p := range s.d.Scope.Allowed() {
		d.Allowed = append(d.Allowed, p.String())
	}
	for _, a := range s.d.Scope.Excluded() {
		d.Excluded = append(d.Excluded, a.String())
	}
	ports := make([]string, len(s.d.Cfg.ScanPorts))
	for i, p := range s.d.Cfg.ScanPorts {
		ports[i] = strconv.Itoa(p)
	}
	d.Ports = strings.Join(ports, ", ")
	for _, p := range s.d.Cfg.TrustedProxies {
		d.Proxies = append(d.Proxies, p.String())
	}
	s.render(w, r, "settings-scope", d)
}

// DojoData is the Integrations → DefectDojo tab. Settings never carries
// the API token.
type DojoData struct {
	Tabs     []SettingsTab
	Settings dojo.Settings
	Status   string // connected | not configured | last push failed | ...
	StatusOK bool
	Error    string
	Check    []CheckRow
	History  []PushRow
}

// CheckRow is one line of the Test connection checklist. State is ok, bad,
// warn or skip.
type CheckRow struct {
	State string
	Text  string
}

// PushRow is one row of the push history.
type PushRow struct {
	Run      string
	At       time.Time
	Trigger  string
	Findings string
	Delta    bool // Added and Closed are known
	Added    int
	Closed   int
	Result   string
	State    string // ok | bad | skipped
}

func (s *Server) dojoSettings(ctx context.Context) (dojo.Settings, error) {
	return dojo.LoadSettings(ctx, s.d.Store, s.d.Box, s.d.Cfg)
}

func (s *Server) dojoPage(w http.ResponseWriter, r *http.Request) {
	s.renderDojo(w, r, http.StatusOK, DojoData{})
}

// renderDojo fills the settings (unless d already has a submitted form),
// the status and the push history, and renders the tab.
func (s *Server) renderDojo(w http.ResponseWriter, r *http.Request, status int, d DojoData) {
	ctx := r.Context()
	d.Tabs = tabs(r, "/settings/integrations")
	if d.Settings == (dojo.Settings{}) {
		st, err := s.dojoSettings(ctx)
		if err != nil {
			s.log.Error("DefectDojo settings", "err", err)
			if d.Error == "" {
				d.Error = "The DefectDojo settings could not be loaded: " + err.Error()
			}
		}
		d.Settings = st
	}
	d.Settings.Token = ""
	d.Status, d.StatusOK = "not configured", false
	if s.d.Pusher != nil {
		chip, err := s.d.Pusher.Status(ctx)
		switch {
		case err != nil:
			d.Status = "status unavailable"
		case !chip.Configured:
		case chip.LastOK == nil:
			d.Status = "configured · no pushes yet"
		case !*chip.LastOK:
			d.Status = "last push failed"
		default:
			d.Status, d.StatusOK = "connected", true
		}
	}
	pushes, err := s.d.Store.DojoPushes(ctx, pushHistoryRows)
	if err != nil {
		s.log.Error("DefectDojo push history", "err", err)
	}
	for _, p := range pushes {
		d.History = append(d.History, pushRow(p))
	}
	s.renderStatus(w, r, status, "settings-dojo", d)
}

func pushRow(p store.DojoPush) PushRow {
	row := PushRow{Run: "–", At: p.At, Trigger: p.Trigger, Findings: "–"}
	if p.RunID != nil {
		row.Run = "#" + strconv.FormatInt(*p.RunID, 10)
	}
	switch {
	case p.Skipped:
		row.State, row.Result = "skipped", "skipped: a newer run was already pushed"
	case p.OK:
		row.State, row.Result = "ok", "reimported"
		if p.Endpoint == "import-scan" {
			row.Result = "imported"
		}
		row.Findings = num(p.Findings)
		row.Delta, row.Added, row.Closed = true, p.Added, p.Closed
	default:
		row.State, row.Result = "bad", p.Error
		if row.Result == "" {
			row.Result = "failed"
		}
	}
	return row
}

// readDojoForm reads the DefectDojo form. The token comes from r.FormValue
// because Settings.Token is never serialised.
func readDojoForm(r *http.Request) dojo.Settings {
	v := func(k string) string { return strings.TrimSpace(r.PostForm.Get(k)) }
	return dojo.Settings{URL: v("url"), ProductType: v("product_type"), Product: v("product"),
		Engagement: v("engagement"), Token: r.FormValue("token"), ClearToken: v("clear_token") != "",
		AutoPush: v("auto_push") != "", CloseMissing: v("close_missing") != ""}
}

func (s *Server) dojoSave(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	if err := r.ParseForm(); err != nil {
		s.renderDojo(w, r, http.StatusBadRequest, DojoData{Error: "The form could not be read."})
		return
	}
	in := readDojoForm(r)
	err := dojo.SaveSettings(r.Context(), s.d.Store, s.d.Box, s.d.Cfg, in)
	switch {
	case errors.Is(err, dojo.ErrManagedByEnv):
		s.renderDojo(w, r, http.StatusConflict, DojoData{Error: "Managed by environment: the DefectDojo " +
			"connection comes from RAMPART_DOJO_* variables and cannot be changed here."})
		return
	case err != nil:
		cur, _ := s.dojoSettings(r.Context())
		in.Token, in.TokenSet = "", cur.TokenSet
		s.renderDojo(w, r, http.StatusUnprocessableEntity, DojoData{Settings: in, Error: err.Error() + "."})
		return
	}
	u, _ := auth.CurrentUser(r.Context())
	s.audit(r, &u.ID, "dojo.settings", "dojo_config", map[string]any{
		"url": in.URL, "product": in.Product, "auto_push": in.AutoPush, "close_missing": in.CloseMissing,
		"token_changed": in.Token != "", "token_cleared": in.ClearToken})
	setFlash(w, r, "DefectDojo settings saved.")
	http.Redirect(w, r, "/settings/integrations", http.StatusSeeOther)
}

// dojoTest runs Client.Check with the stored settings and token and shows
// the checklist. The token is never shown, and is masked in error texts.
func (s *Server) dojoTest(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	u, _ := auth.CurrentUser(ctx)
	st, err := dojo.StoredSettings(s.d.Store, s.d.Box, s.d.Cfg)(ctx)
	var d DojoData
	switch {
	case err != nil:
		d.Error = "The DefectDojo token could not be used: " + err.Error() + "."
	case st.URL == "":
		d.Error = "Set the DefectDojo URL first."
	case st.Token == "":
		d.Error = "Save an API token first."
	default:
		client := s.dojoClient(st)
		res, cerr := client.Check(ctx, st.Product)
		d.Check = checklist(st, res, cerr)
		s.audit(r, &u.ID, "dojo.test", "dojo_config", map[string]any{"ok": cerr == nil && res.CanImport})
		s.renderDojo(w, r, http.StatusOK, d)
		return
	}
	s.audit(r, &u.ID, "dojo.test", "dojo_config", map[string]any{"ok": false})
	s.renderDojo(w, r, http.StatusOK, d)
}

func (s *Server) dojoClient(st dojo.Settings) DojoChecker {
	if s.d.DojoClient != nil {
		return s.d.DojoClient(st)
	}
	return dojo.DefaultClient(st)
}

// checklist turns a Check result into the four checklist rows; rows after
// the first failure are "not checked".
func checklist(st dojo.Settings, res dojo.CheckResult, err error) []CheckRow {
	errText := ""
	if err != nil {
		errText = err.Error()
		if st.Token != "" {
			errText = strings.ReplaceAll(errText, st.Token, "[redacted]")
		}
	}
	reach := "URL reachable"
	if res.Version != "" {
		reach += " (DefectDojo " + res.Version + ")"
	}
	product := "Product \"" + st.Product + "\" exists"
	rows := []CheckRow{
		{State: "ok", Text: reach},
		{State: "ok", Text: "Token valid (user: " + res.User + ")"},
		{State: "ok", Text: "Permission: import / reimport scan"},
		{State: "ok", Text: product},
	}
	if res.User == "" {
		rows[1].Text = "Token valid"
	}
	fail := -1
	switch {
	case !res.Reachable:
		fail, rows[0].Text = 0, "URL not reachable"
	case !res.TokenValid && err == nil:
		fail, rows[1].Text = 1, "Token rejected"
	case !res.TokenValid:
		fail, rows[1].Text = 1, "Token could not be checked"
	case !res.CanImport:
		fail, rows[2].Text = 2, "The token's user may not import scans"
	case err != nil:
		fail, rows[3].Text = 3, "Product could not be checked"
	case st.Product == "":
		rows[3] = CheckRow{State: "warn", Text: "No product set: set one before pushing"}
	case !res.ProductExists:
		rows[3] = CheckRow{State: "warn", Text: "Product \"" + st.Product + "\" not found: it is created on the first push"}
	}
	if fail < 0 {
		return rows
	}
	rows[fail].State = "bad"
	// Check stops at its first error: reaching the server, the token or
	// the product lookup. That error belongs to the failed row unless the
	// token's user simply lacks the import permission.
	if errText != "" && fail != 2 {
		rows[fail].Text += ": " + errText
	}
	for i := fail + 1; i < len(rows); i++ {
		rows[i] = CheckRow{State: "skip", Text: strings.SplitN(rows[i].Text, " (", 2)[0] + " (not checked)"}
	}
	return rows
}

// dojoPush pushes the latest finished run now. The push finishes and is
// recorded even if the browser goes away.
func (s *Server) dojoPush(w http.ResponseWriter, r *http.Request) {
	msg := "DefectDojo is not configured."
	if s.d.Pusher != nil {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), manualPushTimeout)
		rec, err := s.d.Pusher.PushRun(ctx, 0, dojo.TriggerManual)
		cancel()
		msg = pushMessage(rec.RunID, rec, err)
		u, _ := auth.CurrentUser(r.Context())
		s.audit(r, &u.ID, "dojo.push", "scan_run:latest",
			map[string]any{"trigger": dojo.TriggerManual, "run": rec.RunID, "ok": err == nil})
		if err != nil && !errors.Is(err, dojo.ErrNotConfigured) && !errors.Is(err, dojo.ErrStaleRun) {
			s.log.Warn("manual DefectDojo push", "err", err)
		}
	}
	setFlash(w, r, msg)
	http.Redirect(w, r, "/settings/integrations", http.StatusSeeOther)
}

// AuditData is one page of the audit log.
type AuditData struct {
	Tabs    []SettingsTab
	Entries []store.AuditEntry
	Actions []string
	Action  string
	Page    int
	Prev    string
	Next    string
}

func (s *Server) auditPage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	q := r.URL.Query()
	d := AuditData{Tabs: tabs(r, "/settings/audit"), Action: q.Get("action"), Page: 1}
	if p, err := strconv.Atoi(q.Get("page")); err == nil && p > 1 && p <= maxAuditPage {
		d.Page = p
	}
	entries, err := s.d.Store.AuditQuery(ctx, store.AuditFilter{Action: d.Action, Limit: auditPageSize + 1,
		Offset: (d.Page - 1) * auditPageSize})
	if err == nil {
		d.Actions, err = s.d.Store.AuditActions(ctx)
	}
	if err != nil {
		s.log.Error("audit log", "err", err)
		s.serverError(w, r)
		return
	}
	if len(entries) > auditPageSize {
		entries = entries[:auditPageSize]
		d.Next = auditHref(d.Action, d.Page+1)
	}
	if d.Page > 1 {
		d.Prev = auditHref(d.Action, d.Page-1)
	}
	d.Entries = entries
	s.render(w, r, "settings-audit", d)
}

func auditHref(action string, page int) string {
	v := "/settings/audit?"
	if action != "" {
		v += "action=" + url.QueryEscape(action) + "&"
	}
	return v + "page=" + strconv.Itoa(page)
}
