package web

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	"github.com/ctx42/testing/pkg/must"

	"github.com/chrobson/ramparteye/internal/auth"
	"github.com/chrobson/ramparteye/internal/config"
	"github.com/chrobson/ramparteye/internal/dojo"
	"github.com/chrobson/ramparteye/internal/model"
	"github.com/chrobson/ramparteye/internal/runner"
	"github.com/chrobson/ramparteye/internal/scope"
	"github.com/chrobson/ramparteye/internal/store"
	webassets "github.com/chrobson/ramparteye/web"
)

// testNow is the fixed clock of the test servers.
var testNow = time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)

type auditEntry struct {
	UserID  *int64
	Action  string
	Entity  string
	Details any
}

type fakeSession struct {
	userID  int64
	expires time.Time
}

var (
	hashMu sync.Mutex
	hashes = map[string]string{}
)

// hashOf memoises bcrypt hashes; tests reuse a few passwords.
func hashOf(pw string) string {
	hashMu.Lock()
	defer hashMu.Unlock()
	if h, ok := hashes[pw]; ok {
		return h
	}
	h := must.Value(auth.HashPassword(pw))
	hashes[pw] = h
	return h
}

// fakeStore is an in-memory Store.
type fakeStore struct {
	mu       sync.Mutex
	users    map[int64]*store.User
	sessions map[string]fakeSession
	audit    []auditEntry
	nextID   int64

	dash   dashData  // dashboard fixtures
	assets assetData // asset page fixtures
}

// dashData is what the fake store returns for the dashboard queries.
type dashData struct {
	targets  []model.Target
	runs     []store.RunSummary
	allRuns  []store.RunSummary // runs Run finds beyond the recent list
	latest   int64
	changes  []model.Change
	hostObs  []model.HostObs
	services []store.ExportService
	states   []model.HostState
	counts   map[model.HostStateKind]int
	notes    map[model.AssetKey]store.Annotation
}

func newFakeStore() *fakeStore {
	return &fakeStore{users: map[int64]*store.User{}, sessions: map[string]fakeSession{}}
}

// addUser adds a user with the built-in role's permissions and returns it.
func (f *fakeStore) addUser(t *testing.T, login, password, role string, mustChange bool) store.User {
	t.Helper()
	hash := hashOf(password)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nextID++
	var perms []string
	for _, p := range auth.BuiltinRoles[role] {
		perms = append(perms, string(p))
	}
	u := &store.User{ID: f.nextID, Login: login, PasswordHash: hash, RoleName: role,
		Perms: perms, MustChangePassword: mustChange}
	f.users[u.ID] = u
	return *u
}

// session stores a session for userID and returns its cookie.
func (f *fakeStore) session(userID int64) *http.Cookie {
	f.mu.Lock()
	f.nextID++
	tok := fmt.Sprintf("tok-%d", f.nextID)
	f.sessions[string(auth.HashToken(tok))] = fakeSession{userID: userID, expires: testNow.Add(time.Hour)}
	f.mu.Unlock()
	return &http.Cookie{Name: auth.CookieName, Value: tok}
}

func (f *fakeStore) sessionCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.sessions)
}

func (f *fakeStore) auditActions() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, a := range f.audit {
		out = append(out, a.Action)
	}
	return out
}

func (f *fakeStore) lastAudit() auditEntry {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.audit) == 0 {
		return auditEntry{}
	}
	return f.audit[len(f.audit)-1]
}

func (f *fakeStore) user(id int64) store.User {
	f.mu.Lock()
	defer f.mu.Unlock()
	return *f.users[id]
}

func (f *fakeStore) CreateSession(_ context.Context, tokenHash []byte, userID int64, expires time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sessions[string(tokenHash)] = fakeSession{userID: userID, expires: expires}
	return nil
}

func (f *fakeStore) SessionUserAt(_ context.Context, tokenHash []byte, now time.Time) (store.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.sessions[string(tokenHash)]
	if !ok || !now.Before(s.expires) {
		return store.User{}, store.ErrUserNotFound
	}
	u, ok := f.users[s.userID]
	if !ok {
		return store.User{}, store.ErrUserNotFound
	}
	return *u, nil
}

func (f *fakeStore) DeleteSession(_ context.Context, tokenHash []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.sessions, string(tokenHash))
	return nil
}

func (f *fakeStore) DeleteUserSessions(_ context.Context, userID int64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for k, s := range f.sessions {
		if s.userID == userID {
			delete(f.sessions, k)
		}
	}
	return nil
}

func (f *fakeStore) DeleteExpiredSessions(context.Context) (int64, error) { return 0, nil }

func (f *fakeStore) UserByLogin(_ context.Context, login string) (store.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, u := range f.users {
		if u.Login == login {
			return *u, nil
		}
	}
	return store.User{}, store.ErrUserNotFound
}

func (f *fakeStore) UserByID(_ context.Context, id int64) (store.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	u, ok := f.users[id]
	if !ok {
		return store.User{}, store.ErrUserNotFound
	}
	return *u, nil
}

func (f *fakeStore) SetPassword(_ context.Context, userID int64, hash string, mustChange bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	u, ok := f.users[userID]
	if !ok {
		return store.ErrUserNotFound
	}
	u.PasswordHash, u.MustChangePassword = hash, mustChange
	return nil
}

func (f *fakeStore) InsertAudit(_ context.Context, userID *int64, action, entity string, details any) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.audit = append(f.audit, auditEntry{UserID: userID, Action: action, Entity: entity, Details: details})
	return nil
}

// fakeRunner reports fixed active runs.
type fakeRunner struct {
	events    chan runner.Event // Subscribe returns it when set
	unsub     chan struct{}     // closed by the unsubscribe function when set
	active    []int64
	cancelled bool
	cancelBy  int64
}

func (f *fakeRunner) Subscribe() (<-chan runner.Event, func()) {
	if f.events != nil {
		return f.events, func() {
			select {
			case <-f.unsub:
			default:
				close(f.unsub)
			}
		}
	}
	ch := make(chan runner.Event)
	return ch, func() {}
}

func (f *fakeRunner) CancelAll(_ context.Context, by int64) ([]int64, error) {
	f.cancelled, f.cancelBy = true, by
	return f.active, nil
}

func (f *fakeRunner) ActiveRuns() []int64 { return f.active }

// fakePusher returns a fixed chip state.
type fakePusher struct {
	chip dojo.ChipState
	err  error
}

func (f *fakePusher) Status(context.Context) (dojo.ChipState, error) { return f.chip, f.err }

type testEnv struct {
	srv    *Server
	h      http.Handler
	st     *fakeStore
	runner *fakeRunner
	pusher *fakePusher
}

type envOpt func(*Deps)

func withScope(prefixes ...string) envOpt {
	return func(d *Deps) {
		var ps []netip.Prefix
		for _, p := range prefixes {
			ps = append(ps, netip.MustParsePrefix(p))
		}
		d.Scope = must.Value(scope.New(ps, nil, nil))
	}
}

func withTrustedProxies(prefixes ...string) envOpt {
	return func(d *Deps) {
		for _, p := range prefixes {
			d.Cfg.TrustedProxies = append(d.Cfg.TrustedProxies, netip.MustParsePrefix(p))
		}
	}
}

func newEnv(t *testing.T, opts ...envOpt) *testEnv {
	t.Helper()
	return newEnvFS(t, webassets.Templates, opts...)
}

func newEnvFS(t *testing.T, tmpl fs.FS, opts ...envOpt) *testEnv {
	t.Helper()
	e := &testEnv{st: newFakeStore(), runner: &fakeRunner{}, pusher: &fakePusher{}}
	d := Deps{
		Store:  e.st,
		Runner: e.runner,
		Pusher: e.pusher,
		Scope:  must.Value(scope.New([]netip.Prefix{netip.MustParsePrefix("10.20.0.0/18")}, nil, nil)),
		Cfg:    config.Config{MaxRate: 5000, SecretKey: []byte("0123456789abcdef0123456789abcdef")},
		Log:    slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	for _, o := range opts {
		o(&d)
	}
	e.srv = must.Value(newServer(d, tmpl, func() time.Time { return testNow }))
	e.h = e.srv.Handler()
	return e
}

// login adds a user with role and returns its session cookie.
func (e *testEnv) login(t *testing.T, role string) *http.Cookie {
	t.Helper()
	u := e.st.addUser(t, strings.ToLower(role), "correct-horse", role, false)
	return e.st.session(u.ID)
}

func (e *testEnv) get(path string, c *http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if c != nil {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	return rec
}

// post sends a same-origin form POST (as a browser would).
func (e *testEnv) post(path string, form url.Values, c *http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.RemoteAddr = "203.0.113.5:4444"
	if c != nil {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	return rec
}

// overlay returns the embedded templates plus extra files.
func overlay(t *testing.T, extra map[string]string) fs.FS {
	t.Helper()
	m := fstest.MapFS{}
	err := fs.WalkDir(webassets.Templates, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := fs.ReadFile(webassets.Templates, p)
		m[p] = &fstest.MapFile{Data: b}
		return err
	})
	must.Nil(err)
	for name, body := range extra {
		m[name] = &fstest.MapFile{Data: []byte(body)}
	}
	return m
}

func sessionCookie(rec *httptest.ResponseRecorder) *http.Cookie {
	for _, c := range rec.Result().Cookies() {
		if c.Name == auth.CookieName {
			return c
		}
	}
	return nil
}

func (f *fakeStore) Targets(context.Context, string) ([]model.Target, error) {
	return f.dash.targets, nil
}

func (f *fakeStore) Runs(context.Context, int) ([]store.RunSummary, error) {
	return f.dash.runs, nil
}

func (f *fakeStore) LatestDoneRun(context.Context) (int64, error) { return f.dash.latest, nil }

func (f *fakeStore) Changes(context.Context, int64) ([]model.Change, error) {
	return f.dash.changes, nil
}

func (f *fakeStore) RunHostObs(context.Context, int64) ([]model.HostObs, error) {
	return f.dash.hostObs, nil
}

func (f *fakeStore) ExportServices(context.Context, int64) ([]store.ExportService, error) {
	return f.dash.services, nil
}

func (f *fakeStore) HostStates(_ context.Context, state model.HostStateKind) ([]model.HostState, error) {
	var out []model.HostState
	for _, h := range f.dash.states {
		if state == "" || h.State == state {
			out = append(out, h)
		}
	}
	return out, nil
}

func (f *fakeStore) HostStateCounts(context.Context) (map[model.HostStateKind]int, error) {
	return f.dash.counts, nil
}

func (f *fakeStore) AnnotationsByIPs(context.Context, []netip.Addr) (map[model.AssetKey]store.Annotation, error) {
	return f.dash.notes, nil
}

func mustAddr(s string) netip.Addr { return netip.MustParseAddr(s) }

func (f *fakeStore) Run(_ context.Context, id int64) (store.RunSummary, error) {
	for _, r := range f.dash.allRuns {
		if r.ID == id {
			return r, nil
		}
	}
	for _, r := range f.dash.runs {
		if r.ID == id {
			return r, nil
		}
	}
	return store.RunSummary{}, store.ErrRunNotFound
}

// assetData is what the fake store returns for the asset pages.
type assetData struct {
	history  map[model.AssetKey]store.AssetTimeline
	http     map[int64]model.HTTPObs
	sigs     []store.SignatureRow
	upserts  []store.Annotation
	deleted  []model.AssetKey
	failNote error // returned by UpsertAnnotation and DeleteAnnotation
}

func (f *fakeStore) AssetHistory(_ context.Context, k model.AssetKey, _ int) (store.AssetTimeline, error) {
	h := f.assets.history[k]
	h.Key = k
	return h, nil
}

func (f *fakeStore) HTTPObs(_ context.Context, id int64) (model.HTTPObs, error) {
	if o, ok := f.assets.http[id]; ok {
		return o, nil
	}
	return model.HTTPObs{}, store.ErrNotFound
}

func (f *fakeStore) Signatures(context.Context) ([]store.SignatureRow, error) {
	return f.assets.sigs, nil
}

func (f *fakeStore) Annotation(_ context.Context, k model.AssetKey) (store.Annotation, error) {
	if a, ok := f.dash.notes[k]; ok {
		return a, nil
	}
	return store.Annotation{}, store.ErrAnnotationNotFound
}

func (f *fakeStore) UpsertAnnotation(_ context.Context, a store.Annotation) (store.Annotation, error) {
	if f.assets.failNote != nil {
		return a, f.assets.failNote
	}
	if f.dash.notes == nil {
		f.dash.notes = map[model.AssetKey]store.Annotation{}
	}
	f.dash.notes[a.Key] = a
	f.assets.upserts = append(f.assets.upserts, a)
	return a, nil
}

func (f *fakeStore) DeleteAnnotation(_ context.Context, k model.AssetKey, _ int64) error {
	if f.assets.failNote != nil {
		return f.assets.failNote
	}
	if _, ok := f.dash.notes[k]; !ok {
		return store.ErrAnnotationNotFound
	}
	delete(f.dash.notes, k)
	f.assets.deleted = append(f.assets.deleted, k)
	return nil
}
