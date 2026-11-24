// Package web is the server-rendered RampartEye UI: chi routes,
// html/template pages in the theme D shell, htmx for partial updates.
// Scanned content reaches pages only through html/template escaping.
package web

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/chrobson/ramparteye/internal/auth"
	"github.com/chrobson/ramparteye/internal/config"
	"github.com/chrobson/ramparteye/internal/dojo"
	"github.com/chrobson/ramparteye/internal/runner"
	"github.com/chrobson/ramparteye/internal/scope"
	"github.com/chrobson/ramparteye/internal/store"
	webassets "github.com/chrobson/ramparteye/web"
)

// Store is what the UI needs from storage; *store.Store satisfies it.
type Store interface {
	auth.SessionStore
	auth.UserStore
	UserByID(ctx context.Context, id int64) (store.User, error)
	SetPassword(ctx context.Context, userID int64, hash string, mustChange bool) error
	InsertAudit(ctx context.Context, userID *int64, action, entity string, details any) error
}

// Runner is the scan runner as the UI sees it; *runner.Runner satisfies it.
type Runner interface {
	Subscribe() (<-chan runner.Event, func())
	CancelAll(ctx context.Context, by int64) ([]int64, error)
	ActiveRuns() []int64
}

// Pusher reports the DefectDojo chip state; *dojo.Pusher satisfies it.
type Pusher interface {
	Status(ctx context.Context) (dojo.ChipState, error)
}

// Deps are the server's dependencies. Runner and Pusher may be nil (the
// chips then show nothing running / not configured).
type Deps struct {
	Store  Store
	Runner Runner
	Pusher Pusher
	Scope  scope.Scope
	Cfg    config.Config
	Log    *slog.Logger
}

var (
	_ Store  = (*store.Store)(nil)
	_ Runner = (*runner.Runner)(nil)
	_ Pusher = (*dojo.Pusher)(nil)
)

// InstanceHeader marks every response with the installation's id, so the
// scanner can recognise its own web UI when a scan covers its host.
const InstanceHeader = "X-Rampart-Instance"

// InstanceID identifies one installation (shared by `serve` and CLI
// processes): an HMAC of the secret key, or of the database URL when no key
// is set. It reveals neither input.
func InstanceID(cfg config.Config) string {
	key := cfg.SecretKey
	if len(key) == 0 {
		key = []byte(cfg.DatabaseURL)
	}
	m := hmac.New(sha256.New, key)
	m.Write([]byte("rampart-instance-id"))
	return hex.EncodeToString(m.Sum(nil)[:12])
}

// maxFormBytes bounds the body of the login and account forms.
const maxFormBytes = 64 << 10

// Server is the HTTP UI.
type Server struct {
	d        Deps
	log      *slog.Logger
	now      func() time.Time
	auth     *auth.Authenticator
	pages    *pages
	static   fs.FS
	instance string
}

// NewServer parses the embedded templates and returns the server.
func NewServer(d Deps) (*Server, error) {
	return newServer(d, webassets.Templates, time.Now)
}

func newServer(d Deps, tmpl fs.FS, now func() time.Time) (*Server, error) {
	if d.Store == nil {
		return nil, errors.New("web: Deps.Store is required")
	}
	s := &Server{d: d, log: d.Log, now: now, static: webassets.Static, instance: InstanceID(d.Cfg)}
	if s.log == nil {
		s.log = slog.Default()
	}
	s.auth = auth.NewAuthenticator(d.Store, d.Store, now)
	p, err := parsePages(tmpl, s.funcs())
	if err != nil {
		return nil, err
	}
	s.pages = p
	return s, nil
}

// Handler returns the router. Every request passes the recoverer, security
// headers, the instance header and CSRF protection; everything except
// static files also passes the session middleware.
func (s *Server) Handler() http.Handler {
	r := chi.NewRouter()
	r.Use(s.recoverer, securityHeaders, s.instanceHeader, auth.CSRF)
	r.Handle(auth.StaticPrefix+"*", http.StripPrefix(auth.StaticPrefix, s.staticHandler()))

	session := auth.Middleware(s.d.Store, s.now)
	r.NotFound(session(http.HandlerFunc(s.notFound)).ServeHTTP)
	r.MethodNotAllowed(session(http.HandlerFunc(s.methodNotAllowed)).ServeHTTP)
	r.Group(func(r chi.Router) {
		r.Use(session)
		r.Get("/login", s.loginPage)
		r.Post("/login", s.loginSubmit)
		r.Post(auth.LogoutPath, s.logout)
		r.With(s.requireUser).Get(auth.PasswordPath, s.passwordPage)
		r.With(s.requireUser).Post(auth.PasswordPath, s.passwordSubmit)

		// Placeholder pages; Tasks 21-24 replace them.
		for _, n := range navItems {
			r.With(s.require(n.Perm)).Get(n.Href, s.stubPage(n.Label))
		}
	})
	return r
}

// stubPage renders an empty themed page.
func (s *Server) stubPage(title string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.render(w, r, "stub", map[string]string{"Title": title})
	}
}

// requireUser demands a session: 401 for API and htmx requests, else a 303
// to /login with the current page as next (GET only).
func (s *Server) requireUser(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := auth.CurrentUser(r.Context()); !ok {
			unauthorized(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// require demands a session and perm; a missing permission gets the
// themed 403 page.
func (s *Server) require(perm auth.Perm) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return s.requireUser(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !auth.Can(r.Context(), perm) {
				s.forbidden(w, r, perm)
				return
			}
			next.ServeHTTP(w, r)
		}))
	}
}

func unauthorized(w http.ResponseWriter, r *http.Request) {
	if auth.IsAPIRequest(r) {
		if r.Header.Get("HX-Request") == "true" {
			w.Header().Set("HX-Redirect", "/login")
		}
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	next := r.URL.RequestURI()
	if r.Method != http.MethodGet {
		next = "/"
	}
	http.Redirect(w, r, "/login?next="+url.QueryEscape(next), http.StatusSeeOther)
}

func (s *Server) staticHandler() http.Handler {
	files := http.FileServer(http.FS(s.static))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "" || strings.HasSuffix(r.URL.Path, "/") {
			http.NotFound(w, r) // no directory listings
			return
		}
		// Asset URLs carry a content hash (?v=), so they may be cached.
		w.Header().Set("Cache-Control", "public, max-age=86400")
		files.ServeHTTP(w, r)
	})
}

// csp allows scripts and styles only from this origin. Style attributes
// are allowed (dynamic widths of bars); html/template sanitises CSS
// contexts. htmx is configured not to inject styles or evaluate code.
const csp = "default-src 'self'; script-src 'self'; style-src 'self'; style-src-attr 'unsafe-inline'; " +
	"img-src 'self' data:; connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; " +
	"form-action 'self'; frame-ancestors 'none'"

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "same-origin")
		h.Set("Content-Security-Policy", csp)
		next.ServeHTTP(w, r)
	})
}

func (s *Server) instanceHeader(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(InstanceHeader, s.instance)
		next.ServeHTTP(w, r)
	})
}

// recoverer turns a panic into the themed 500 page.
func (s *Server) recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if v := recover(); v != nil {
				if v == http.ErrAbortHandler {
					panic(v)
				}
				s.log.Error("panic in handler", "path", r.URL.Path, "panic", v)
				s.serverError(w, r)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// safeNext accepts only local absolute paths, preventing open redirects.
func safeNext(s string) string {
	if !strings.HasPrefix(s, "/") || strings.HasPrefix(s, "//") || strings.HasPrefix(s, "/\\") {
		return "/"
	}
	for _, c := range s {
		if c < 0x20 || c == 0x7f {
			return "/" // browsers drop tabs and newlines: "/\t/evil" is "//evil"
		}
	}
	return s
}

// clientIP returns the bare client address (no port). X-Forwarded-For is
// used only when the direct peer is a trusted proxy: the rightmost entry
// that is not itself a trusted proxy is the client. An unparsable entry
// ends the walk at the last trusted hop.
func clientIP(r *http.Request, trusted []netip.Prefix) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	peer, err := netip.ParseAddr(strings.Trim(host, "[]"))
	if err != nil {
		return host
	}
	peer = peer.Unmap().WithZone("")
	if !isTrusted(peer, trusted) {
		return peer.String()
	}
	var hops []string
	for _, v := range r.Header.Values("X-Forwarded-For") {
		hops = append(hops, strings.Split(v, ",")...)
	}
	client := peer
	for i := len(hops) - 1; i >= 0; i-- {
		a, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
		if err != nil {
			break
		}
		client = a.Unmap().WithZone("")
		if !isTrusted(client, trusted) {
			break
		}
	}
	return client.String()
}

func isTrusted(a netip.Addr, trusted []netip.Prefix) bool {
	for _, p := range trusted {
		if p.Contains(a) {
			return true
		}
	}
	return false
}
