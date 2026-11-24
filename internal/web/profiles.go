package web

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/go-chi/chi/v5"

	"github.com/chrobson/ramparteye/internal/auth"
	"github.com/chrobson/ramparteye/internal/config"
	"github.com/chrobson/ramparteye/internal/model"
	"github.com/chrobson/ramparteye/internal/runner"
	"github.com/chrobson/ramparteye/internal/scope"
	"github.com/chrobson/ramparteye/internal/store"
)

// Scan profile limits.
const (
	maxProfileName = 100  // runes
	maxPortList    = 2000 // bytes of a port list field
	maxWorkers     = 64
	minEveryMin    = 5
	maxEveryMin    = 60 * 24 * 31
)

var portProfiles = []PortProfileOption{
	{runner.ProfileAuto, "Automatic: every port for small targets, else the most common ports"},
	{runner.ProfileTop, "Most common ports, plus common infrastructure ports"},
	{runner.ProfileList, "Own port list"},
	{runner.ProfileAll, "Every TCP port 1–65535"},
}

// PortProfileOption is a choice of the port profile select.
type PortProfileOption struct{ Key, Label string }

// ProfileRow is a scan profile on the list.
type ProfileRow struct {
	ID       int64
	Name     string
	Targets  string
	Ports    string
	MaxRate  int
	Workers  int
	Window   string
	Schedule string
	Enabled  bool
	LastRun  *LastRun
}

// LastRun is the newest run of a profile.
type LastRun struct {
	ID     int64
	Status RunStatus
}

// ProfilesData is the scan profiles page.
type ProfilesData struct {
	Title    string
	Profiles []ProfileRow
	MaxRate  int
}

// ProfileForm is the create/edit form of a scan profile, holding the
// submitted text so a rejected form shows what was typed.
type ProfileForm struct {
	Title       string
	New         bool
	Action      string
	Error       string
	ID          int64
	Name        string
	AllTargets  bool
	TargetIDs   []int64
	PortProfile string
	TopPorts    string
	Ports       string
	ExtraPorts  bool
	ExtraList   string
	MaxRate     string
	Workers     string
	WindowStart string
	WindowEnd   string
	Every       string
	Enabled     bool

	Targets      []model.Target
	Profiles     []PortProfileOption
	RateCap      int
	AllowedPorts string
	AllPortsMax  int
	ChunkInfo    string
}

func clock(d *time.Duration) string {
	if d == nil {
		return ""
	}
	m := int(*d / time.Minute)
	return fmt.Sprintf("%02d:%02d", m/60%24, m%60)
}

func formFromConfig(c store.ScanConfig) ProfileForm {
	f := ProfileForm{ID: c.ID, Name: c.Name, AllTargets: len(c.TargetIDs) == 0, TargetIDs: c.TargetIDs,
		PortProfile: runner.ProfileOf(c), TopPorts: strconv.Itoa(c.TopPorts), Ports: c.Ports,
		ExtraPorts: c.ExtraPorts, ExtraList: c.ExtraPortList, MaxRate: strconv.Itoa(c.MaxRate),
		Workers: strconv.Itoa(c.Workers), WindowStart: clock(c.WindowStart), WindowEnd: clock(c.WindowEnd),
		Enabled: c.Enabled}
	if c.EveryMinutes != nil {
		f.Every = strconv.Itoa(*c.EveryMinutes)
	}
	return f
}

// formFromRequest copies the submitted fields without validating them.
func formFromRequest(r *http.Request) ProfileForm {
	v := func(k string) string { return strings.TrimSpace(r.PostForm.Get(k)) }
	f := ProfileForm{Name: v("name"), AllTargets: v("all_targets") != "", PortProfile: v("port_profile"),
		TopPorts: v("top_ports"), Ports: v("ports"), ExtraPorts: v("extra_ports") != "",
		ExtraList: v("extra_port_list"), MaxRate: v("max_rate"), Workers: v("workers"),
		WindowStart: v("window_start"), WindowEnd: v("window_end"), Every: v("every_minutes"),
		Enabled: v("enabled") != ""}
	for _, s := range r.PostForm["target_ids"] {
		if id, err := strconv.ParseInt(s, 10, 64); err == nil {
			f.TargetIDs = append(f.TargetIDs, id)
		}
	}
	return f
}

// rateCap is the highest packets/s a profile may set (RAMPART_MAX_RATE).
func (s *Server) rateCap() int {
	if s.d.Cfg.MaxRate > 0 {
		return s.d.Cfg.MaxRate
	}
	return config.DefaultMaxRate
}

// formInt parses a whole number in [lo, hi]; empty gives def.
func formInt(v, label string, def, lo, hi int) (int, error) {
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < lo || n > hi {
		return 0, fmt.Errorf("%s must be a whole number between %d and %d.", label, lo, hi)
	}
	return n, nil
}

// parseClock parses "HH:MM" (empty = nil).
func parseClock(v, label string) (*time.Duration, error) {
	if v == "" {
		return nil, nil
	}
	t, err := time.Parse("15:04", v)
	if err != nil {
		return nil, fmt.Errorf("%s must be a time of day as HH:MM.", label)
	}
	d := time.Duration(t.Hour())*time.Hour + time.Duration(t.Minute())*time.Minute
	return &d, nil
}

// portList validates a port list field with config.ParsePorts and returns
// it normalised.
func portList(v, label string) (string, error) {
	if len(v) > maxPortList {
		return "", fmt.Errorf("%s is too long.", label)
	}
	ps, err := config.ParsePorts(v)
	if err != nil {
		return "", fmt.Errorf("%s: %v.", label, err)
	}
	return config.FormatPorts(ps), nil
}

// validate turns the form into a scan profile. known lists the target ids
// that exist.
func (s *Server) validateProfile(f ProfileForm, known map[int64]bool) (store.ScanConfig, error) {
	c := store.ScanConfig{ID: f.ID, Name: f.Name, Enabled: f.Enabled, ExtraPorts: f.ExtraPorts, TargetIDs: []int64{}}
	if c.Name == "" || utf8.RuneCountInString(c.Name) > maxProfileName || !utf8.ValidString(c.Name) {
		return c, fmt.Errorf("Name is required (at most %d characters).", maxProfileName)
	}
	if !slices.ContainsFunc(portProfiles, func(o PortProfileOption) bool { return o.Key == f.PortProfile }) {
		return c, errors.New("Unknown port profile.")
	}
	c.PortProfile = f.PortProfile
	var err error
	if c.TopPorts, err = formInt(f.TopPorts, "Top ports", 1000, 1, 65535); err != nil {
		return c, err
	}
	if c.Ports, err = portList(f.Ports, "Port list"); err != nil {
		return c, err
	}
	if c.PortProfile == runner.ProfileList && c.Ports == "" {
		return c, errors.New("The own port list profile needs a port list.")
	}
	if c.ExtraPortList, err = portList(f.ExtraList, "Extra ports"); err != nil {
		return c, err
	}
	if _, err := runner.ResolvePorts(c, 0, 0, s.d.Cfg.ScanPorts, nil); err != nil {
		return c, fmt.Errorf("Ports: %v.", err)
	}
	maxRate := s.rateCap()
	if c.MaxRate, err = formInt(f.MaxRate, "Rate", min(1000, maxRate), 1, maxRate); err != nil {
		return c, fmt.Errorf("Rate must be between 1 and %d packets/s (RAMPART_MAX_RATE).", maxRate)
	}
	if c.Workers, err = formInt(f.Workers, "Parallel chunks", 4, 1, maxWorkers); err != nil {
		return c, err
	}
	if c.WindowStart, err = parseClock(f.WindowStart, "Window start"); err != nil {
		return c, err
	}
	if c.WindowEnd, err = parseClock(f.WindowEnd, "Window end"); err != nil {
		return c, err
	}
	if (c.WindowStart == nil) != (c.WindowEnd == nil) {
		return c, errors.New("A time window needs both a start and an end (or neither).")
	}
	if f.Every != "" {
		n, err := formInt(f.Every, "Repeat every", 0, minEveryMin, maxEveryMin)
		if err != nil {
			return c, fmt.Errorf("Repeat every must be between %d and %d minutes (31 days).", minEveryMin, maxEveryMin)
		}
		c.EveryMinutes = &n
	}
	if !f.AllTargets {
		for _, id := range f.TargetIDs {
			if !known[id] {
				return c, errors.New("The profile names an unknown target. Reload the page and choose again.")
			}
			if !slices.Contains(c.TargetIDs, id) {
				c.TargetIDs = append(c.TargetIDs, id)
			}
		}
		if len(c.TargetIDs) == 0 {
			return c, errors.New("Choose targets, or tick All targets.")
		}
	}
	return c, nil
}

// portsLabel describes the port selection of a profile.
func (s *Server) portsLabel(c store.ScanConfig) string {
	switch runner.ProfileOf(c) {
	case runner.ProfileAll:
		return "every port (-p-)"
	case runner.ProfileList:
		return "list " + c.Ports
	case runner.ProfileTop:
		l := fmt.Sprintf("top %d", c.TopPorts)
		if c.ExtraPorts {
			l += " + infrastructure"
		}
		if c.ExtraPortList != "" {
			l += " + " + c.ExtraPortList
		}
		return l
	}
	if n := s.d.Cfg.AllPortsMaxAddrs; n > 0 {
		return fmt.Sprintf("auto: every port up to %d addresses, else top %d", n, c.TopPorts)
	}
	return fmt.Sprintf("auto: top %d", c.TopPorts)
}

func (s *Server) profilesList(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	cfgs, err := s.d.Store.ScanConfigs(ctx)
	if err != nil {
		s.log.Error("list scan profiles", "err", err)
		s.serverError(w, r)
		return
	}
	d := ProfilesData{Title: "Scan profiles", MaxRate: s.rateCap()}
	for _, c := range cfgs {
		row := ProfileRow{ID: c.ID, Name: c.Name, Targets: "all targets", Ports: s.portsLabel(c),
			MaxRate: c.MaxRate, Workers: c.Workers, Window: "no window", Schedule: "manual only", Enabled: c.Enabled}
		if n := len(c.TargetIDs); n > 0 {
			row.Targets = plural(n, "target", "targets")
		}
		if c.HasWindow() {
			row.Window = clock(c.WindowStart) + "–" + clock(c.WindowEnd)
		}
		if c.EveryMinutes != nil {
			row.Schedule = "every " + strconv.Itoa(*c.EveryMinutes) + " min"
		}
		last, err := s.d.Store.LastRun(ctx, c.ID)
		if err != nil {
			s.log.Error("last run of scan profile", "id", c.ID, "err", err)
			s.serverError(w, r)
			return
		}
		if last != nil {
			row.LastRun = &LastRun{ID: last.ID, Status: runStatus(last.Status)}
		}
		d.Profiles = append(d.Profiles, row)
	}
	s.render(w, r, "profiles", d)
}

func (s *Server) profileNew(w http.ResponseWriter, r *http.Request) {
	f := ProfileForm{New: true, AllTargets: true, PortProfile: runner.ProfileAuto, TopPorts: "1000",
		MaxRate: strconv.Itoa(min(1000, s.rateCap())), Workers: "4", ExtraPorts: true, Enabled: true}
	s.renderProfileForm(w, r, http.StatusOK, f)
}

func (s *Server) profileEdit(w http.ResponseWriter, r *http.Request) {
	c, ok := s.loadProfile(w, r)
	if !ok {
		return
	}
	s.renderProfileForm(w, r, http.StatusOK, formFromConfig(c))
}

// loadProfile returns the scan profile of the {id} parameter or writes a
// not found / error page.
func (s *Server) loadProfile(w http.ResponseWriter, r *http.Request) (store.ScanConfig, bool) {
	id, ok := pathID(r, "id")
	if !ok {
		s.notFound(w, r)
		return store.ScanConfig{}, false
	}
	c, err := s.d.Store.ScanConfig(r.Context(), id)
	switch {
	case errors.Is(err, store.ErrNotFound):
		s.notFound(w, r)
		return c, false
	case err != nil:
		s.log.Error("load scan profile", "id", id, "err", err)
		s.serverError(w, r)
		return c, false
	}
	return c, true
}

func (s *Server) renderProfileForm(w http.ResponseWriter, r *http.Request, status int, f ProfileForm) {
	ts, err := s.d.Store.Targets(r.Context(), "")
	if err != nil {
		s.log.Error("list targets", "err", err)
		s.serverError(w, r)
		return
	}
	f.Targets, f.Profiles, f.RateCap = ts, portProfiles, s.rateCap()
	f.AllowedPorts, f.AllPortsMax = config.FormatPorts(s.d.Cfg.ScanPorts), s.d.Cfg.AllPortsMaxAddrs
	f.ChunkInfo = "Targets are split into chunks of /24 (IPv4); each parallel chunk gets an equal share of the rate."
	if f.New {
		f.Title, f.Action = "New scan profile", "/profiles"
	} else {
		f.Title, f.Action = "Scan profile: "+f.Name, "/profiles/"+strconv.FormatInt(f.ID, 10)
	}
	s.renderStatus(w, r, status, "profile", f)
}

func (s *Server) profileSave(w http.ResponseWriter, r *http.Request) {
	var id int64
	if chi.URLParam(r, "id") != "" {
		c, ok := s.loadProfile(w, r)
		if !ok {
			return
		}
		id = c.ID
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	if err := r.ParseForm(); err != nil {
		s.renderError(w, r, errorData{Code: http.StatusBadRequest, Title: "Invalid form",
			Text: "The form could not be read."})
		return
	}
	f := formFromRequest(r)
	f.ID, f.New = id, id == 0
	ctx := r.Context()
	known, err := s.targetIDs(ctx)
	if err != nil {
		s.log.Error("list targets", "err", err)
		s.serverError(w, r)
		return
	}
	c, err := s.validateProfile(f, known)
	if err == nil {
		if id == 0 {
			c.ID, err = s.d.Store.CreateScanConfig(ctx, c)
		} else {
			err = s.d.Store.UpdateScanConfig(ctx, c)
		}
		switch {
		case errors.Is(err, store.ErrScanConfigNameTaken):
			err = errors.New("A scan profile with this name already exists.")
		case err != nil:
			s.log.Error("save scan profile", "err", err)
			s.serverError(w, r)
			return
		}
	}
	if err != nil {
		f.Error = err.Error()
		s.renderProfileForm(w, r, http.StatusUnprocessableEntity, f)
		return
	}
	u, _ := auth.CurrentUser(ctx)
	s.audit(r, &u.ID, "scan_config.save", "scan_config:"+strconv.FormatInt(c.ID, 10),
		map[string]any{"name": c.Name, "targets": len(c.TargetIDs), "max_rate": c.MaxRate})
	setFlash(w, r, fmt.Sprintf("Scan profile %q saved.", c.Name))
	http.Redirect(w, r, "/profiles", http.StatusSeeOther)
}

func (s *Server) targetIDs(ctx context.Context) (map[int64]bool, error) {
	ts, err := s.d.Store.Targets(ctx, "")
	if err != nil {
		return nil, err
	}
	out := make(map[int64]bool, len(ts))
	for _, t := range ts {
		out[t.ID] = true
	}
	return out, nil
}

func (s *Server) profileDelete(w http.ResponseWriter, r *http.Request) {
	c, ok := s.loadProfile(w, r)
	if !ok {
		return
	}
	err := s.d.Store.DeleteScanConfig(r.Context(), c.ID)
	switch {
	case errors.Is(err, store.ErrScanConfigBusy):
		setFlash(w, r, fmt.Sprintf("Scan profile %q has an unfinished run; cancel it first.", c.Name))
	case errors.Is(err, store.ErrNotFound):
		setFlash(w, r, "The scan profile no longer exists.")
	case err != nil:
		s.log.Error("delete scan profile", "id", c.ID, "err", err)
		s.serverError(w, r)
		return
	default:
		u, _ := auth.CurrentUser(r.Context())
		s.audit(r, &u.ID, "scan_config.delete", "scan_config:"+strconv.FormatInt(c.ID, 10),
			map[string]any{"name": c.Name})
		setFlash(w, r, fmt.Sprintf("Scan profile %q deleted.", c.Name))
	}
	http.Redirect(w, r, "/profiles", http.StatusSeeOther)
}

// profileRun starts a manual run of a profile.
func (s *Server) profileRun(w http.ResponseWriter, r *http.Request) {
	c, ok := s.loadProfile(w, r)
	if !ok {
		return
	}
	if s.d.Runner == nil {
		setFlash(w, r, "No scan runner is available in this process.")
		http.Redirect(w, r, "/profiles", http.StatusSeeOther)
		return
	}
	runID, err := s.d.Runner.Start(s.runContext(r), c.ID)
	if err != nil {
		setFlash(w, r, startMessage(c.Name, err))
		if !errors.Is(err, scope.ErrNoScope) && !errors.Is(err, runner.ErrAlreadyRunning) &&
			!errors.Is(err, runner.ErrNoTargets) {
			s.log.Error("start scan", "profile", c.ID, "err", err)
		}
		http.Redirect(w, r, "/profiles", http.StatusSeeOther)
		return
	}
	u, _ := auth.CurrentUser(r.Context())
	s.audit(r, &u.ID, "scan.start", "scan_run:"+strconv.FormatInt(runID, 10),
		map[string]any{"profile": c.ID, "name": c.Name})
	setFlash(w, r, "Scan #"+strconv.FormatInt(runID, 10)+" started.")
	http.Redirect(w, r, "/scans/"+strconv.FormatInt(runID, 10), http.StatusSeeOther)
}

func startMessage(name string, err error) string {
	switch {
	case errors.Is(err, scope.ErrNoScope):
		return "No scan scope configured: set RAMPART_ALLOWED_CIDRS. Every scan is refused until a scope is set."
	case errors.Is(err, runner.ErrAlreadyRunning):
		return fmt.Sprintf("A run of %q is already running.", name)
	case errors.Is(err, runner.ErrNoTargets):
		return fmt.Sprintf("Scan profile %q has no targets inside the scan scope.", name)
	}
	return "The scan could not be started; see the server log."
}

// runContext is the context manual runs execute under: they must outlive
// the request, but end with the server.
func (s *Server) runContext(r *http.Request) context.Context {
	if s.d.ShutdownCtx != nil {
		return s.d.ShutdownCtx
	}
	return context.WithoutCancel(r.Context())
}

// hasID reports whether ids holds id (template helper).
func hasID(ids []int64, id int64) bool { return slices.Contains(ids, id) }
