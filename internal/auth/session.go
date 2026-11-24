package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/chrobson/ramparteye/internal/store"
)

const (
	// CookieName is the session cookie.
	CookieName = "rampart_session"
	// SessionTTL is the lifetime of a session.
	SessionTTL = 12 * time.Hour
	// PasswordPath is the page a user with a forced password change is sent to.
	PasswordPath = "/account/password"
	// LogoutPath is always reachable, even before the password is changed.
	LogoutPath = "/logout"
	// StaticPrefix is the path prefix of static assets.
	StaticPrefix = "/static/"
)

var (
	// ErrBadCredentials is returned for an unknown login or wrong password.
	ErrBadCredentials = errors.New("invalid login or password")
	// ErrLocked is returned while the login or client is throttled.
	ErrLocked = errors.New("too many failed logins")
)

// SessionStore is what the middleware needs from storage; *store.Store
// satisfies it.
type SessionStore interface {
	CreateSession(ctx context.Context, tokenHash []byte, userID int64, expires time.Time) error
	// SessionUserAt returns the user of a session not expired at now, or
	// store.ErrUserNotFound.
	SessionUserAt(ctx context.Context, tokenHash []byte, now time.Time) (store.User, error)
	DeleteSession(ctx context.Context, tokenHash []byte) error
}

// UserStore looks users up by login for Login; *store.Store satisfies it.
type UserStore interface {
	UserByLogin(ctx context.Context, login string) (store.User, error)
}

func newToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b) // never fails since Go 1.24
	return base64.RawURLEncoding.EncodeToString(b)
}

// HashToken returns the SHA-256 stored in place of a session token.
func HashToken(tok string) []byte {
	h := sha256.Sum256([]byte(tok))
	return h[:]
}

func fromStore(u store.User) User {
	perms := make([]Perm, len(u.Perms))
	for i, p := range u.Perms {
		perms[i] = Perm(p)
	}
	return User{ID: u.ID, Login: u.Login, RoleName: u.RoleName, Perms: perms,
		MustChangePassword: u.MustChangePassword}
}

// Authenticator verifies credentials, throttles failures and issues
// sessions.
type Authenticator struct {
	Users    UserStore
	Sessions SessionStore
	now      func() time.Time
	throttle *throttle
}

// NewAuthenticator returns an Authenticator using now as its clock.
func NewAuthenticator(users UserStore, sessions SessionStore, now func() time.Time) *Authenticator {
	return &Authenticator{Users: users, Sessions: sessions, now: now, throttle: newThrottle(now)}
}

// Login checks the credentials and creates a session. ip is the client
// address used for throttling. It returns the cookie token and expiry.
// Errors: ErrLocked, ErrBadCredentials, or a storage error.
func (a *Authenticator) Login(ctx context.Context, login, password, ip string) (string, time.Time, error) {
	keys := throttleKeys(login, ip)
	if blocked, _ := a.throttle.blocked(keys...); blocked {
		return "", time.Time{}, ErrLocked
	}
	u, err := a.Users.UserByLogin(ctx, login)
	switch {
	case errors.Is(err, store.ErrUserNotFound):
		CheckPassword(string(dummyHash), password) // equalise timing
		a.throttle.fail(keys...)
		return "", time.Time{}, ErrBadCredentials
	case err != nil:
		return "", time.Time{}, err
	}
	if !CheckPassword(u.PasswordHash, password) {
		a.throttle.fail(keys...)
		return "", time.Time{}, ErrBadCredentials
	}
	a.throttle.reset(keys[0])
	tok := newToken()
	expires := a.now().Add(SessionTTL)
	if err := a.Sessions.CreateSession(ctx, HashToken(tok), u.ID, expires); err != nil {
		return "", time.Time{}, err
	}
	return tok, expires, nil
}

// Logout deletes the session named by the request cookie, if any.
func (a *Authenticator) Logout(ctx context.Context, r *http.Request) error {
	c, err := r.Cookie(CookieName)
	if err != nil || c.Value == "" {
		return nil
	}
	return a.Sessions.DeleteSession(ctx, HashToken(c.Value))
}

func isTLS(r *http.Request) bool {
	return r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

// SetSessionCookie sets the session cookie: HttpOnly, SameSite=Lax, Secure
// when the request is TLS.
func SetSessionCookie(w http.ResponseWriter, r *http.Request, tok string, expires, now time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name: CookieName, Value: tok, Path: "/", Expires: expires,
		MaxAge:   int(expires.Sub(now).Seconds()),
		HttpOnly: true, Secure: isTLS(r), SameSite: http.SameSiteLaxMode,
	})
}

// ClearSessionCookie expires the session cookie.
func ClearSessionCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name: CookieName, Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: isTLS(r), SameSite: http.SameSiteLaxMode,
	})
}

// Middleware loads the session user into the request context and enforces
// the forced password change: while MustChangePassword is set, every request
// except the password page, logout and static assets gets a 303 to
// PasswordPath. Requests without a valid session pass through unauthenticated;
// use Require to demand a user or permission.
func Middleware(st SessionStore, now func() time.Time) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c, err := r.Cookie(CookieName)
			if err != nil || c.Value == "" {
				next.ServeHTTP(w, r)
				return
			}
			su, err := st.SessionUserAt(r.Context(), HashToken(c.Value), now())
			if errors.Is(err, store.ErrUserNotFound) {
				next.ServeHTTP(w, r)
				return
			}
			if err != nil {
				slog.Error("session lookup", "err", err)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			u := fromStore(su)
			if u.MustChangePassword && !passwordChangeExempt(r.URL.Path) {
				http.Redirect(w, r, PasswordPath, http.StatusSeeOther)
				return
			}
			next.ServeHTTP(w, r.WithContext(WithUser(r.Context(), u)))
		})
	}
}

func passwordChangeExempt(path string) bool {
	return path == PasswordPath || path == LogoutPath || strings.HasPrefix(path, StaticPrefix)
}

// Require demands perm. No session: 401 for API and htmx requests, else a
// 303 to /login. Missing permission: 403.
func Require(perm Perm) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			u, ok := CurrentUser(r.Context())
			if !ok {
				unauthorized(w, r)
				return
			}
			if !u.Can(perm) {
				http.Error(w, "forbidden: missing permission "+string(perm), http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// IsAPIRequest reports whether the client expects an error status instead
// of a redirect: /api/ paths, htmx requests and Accept: application/json.
func IsAPIRequest(r *http.Request) bool {
	if strings.HasPrefix(r.URL.Path, "/api/") || r.Header.Get("HX-Request") == "true" {
		return true
	}
	acc := r.Header.Get("Accept")
	return strings.Contains(acc, "application/json") && !strings.Contains(acc, "text/html")
}

func unauthorized(w http.ResponseWriter, r *http.Request) {
	if IsAPIRequest(r) {
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
