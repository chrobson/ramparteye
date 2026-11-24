package web

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/chrobson/ramparteye/internal/auth"
)

// loginData is the data of the login page.
type loginData struct {
	Next  string
	Login string
	Error string
}

// passwordData is the data of the password page. Forced is set while the
// user must change the password before doing anything else.
type passwordData struct {
	Forced bool
	Error  string
}

// maxLoggedLogin bounds a login name copied into the audit log.
const maxLoggedLogin = 64

func (s *Server) loginPage(w http.ResponseWriter, r *http.Request) {
	next := safeNext(r.URL.Query().Get("next"))
	if _, ok := auth.CurrentUser(r.Context()); ok {
		http.Redirect(w, r, next, http.StatusSeeOther)
		return
	}
	s.render(w, r, "login", loginData{Next: next})
}

func (s *Server) loginSubmit(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	if err := r.ParseForm(); err != nil {
		s.renderStatus(w, r, http.StatusBadRequest, "login", loginData{Next: "/", Error: "The form could not be read."})
		return
	}
	ctx := r.Context()
	login := strings.TrimSpace(r.PostForm.Get("login"))
	next := safeNext(r.PostForm.Get("next"))
	ip := clientIP(r, s.d.Cfg.TrustedProxies)
	tok, exp, err := s.auth.Login(ctx, login, r.PostForm.Get("password"), ip)
	var locked *auth.LockedError
	switch {
	case errors.As(err, &locked):
		logged := loggedLogin(login)
		s.audit(r, nil, "login.locked", "user:"+logged, map[string]any{"login": logged, "ip": ip})
		s.renderStatus(w, r, http.StatusTooManyRequests, "login", loginData{Next: next, Login: login,
			Error: lockedMessage(w, "logins", locked)})
		return
	case errors.Is(err, auth.ErrBadCredentials):
		logged := loggedLogin(login)
		s.audit(r, nil, "login.failed", "user:"+logged, map[string]any{"login": logged, "ip": ip})
		s.renderStatus(w, r, http.StatusUnauthorized, "login", loginData{Next: next, Login: login,
			Error: "Invalid login or password."})
		return
	case err != nil:
		s.log.Error("login", "err", err)
		s.serverError(w, r)
		return
	}
	// A session already on this browser is replaced, not left behind.
	if err := s.auth.Logout(ctx, r); err != nil {
		s.log.Warn("delete previous session on login", "err", err)
	}
	auth.SetSessionCookie(w, r, tok, exp, s.now())
	var uid *int64
	if u, err := s.d.Store.UserByLogin(ctx, login); err == nil {
		uid = &u.ID
	}
	s.audit(r, uid, "login", "user:"+login, map[string]any{"ip": ip})
	http.Redirect(w, r, next, http.StatusSeeOther)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if err := s.auth.Logout(r.Context(), r); err != nil {
		s.log.Error("logout", "err", err)
		s.serverError(w, r)
		return
	}
	if u, ok := auth.CurrentUser(r.Context()); ok {
		s.audit(r, &u.ID, "logout", "user:"+u.Login, nil)
	}
	auth.ClearSessionCookie(w, r)
	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("HX-Redirect", "/login")
		w.WriteHeader(http.StatusNoContent)
		return
	}
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (s *Server) passwordPage(w http.ResponseWriter, r *http.Request) {
	u, _ := auth.CurrentUser(r.Context())
	s.render(w, r, "password", passwordData{Forced: u.MustChangePassword})
}

func (s *Server) passwordSubmit(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	u, _ := auth.CurrentUser(ctx)
	fail := func(msg string) {
		s.renderStatus(w, r, http.StatusUnprocessableEntity, "password",
			passwordData{Forced: u.MustChangePassword, Error: msg})
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	if err := r.ParseForm(); err != nil {
		fail("The form could not be read.")
		return
	}
	cur, next, confirm := r.PostForm.Get("current"), r.PostForm.Get("new"), r.PostForm.Get("confirm")
	// The current password is checked like a login: throttled per login
	// and client address.
	ip := clientIP(r, s.d.Cfg.TrustedProxies)
	err := s.auth.Verify(ctx, u.Login, cur, ip)
	var locked *auth.LockedError
	switch {
	case errors.As(err, &locked):
		s.audit(r, &u.ID, "user.password.locked", "user:"+u.Login, map[string]any{"ip": ip})
		s.renderStatus(w, r, http.StatusTooManyRequests, "password",
			passwordData{Forced: u.MustChangePassword, Error: lockedMessage(w, "password checks", locked)})
		return
	case errors.Is(err, auth.ErrBadCredentials):
		s.audit(r, &u.ID, "user.password.failed", "user:"+u.Login, map[string]any{"ip": ip})
		fail("Current password is incorrect.")
		return
	case err != nil:
		s.log.Error("verify current password", "err", err)
		s.serverError(w, r)
		return
	}
	switch {
	case next != confirm:
		fail("The new passwords do not match.")
		return
	case next == cur:
		fail("The new password must differ from the current one.")
		return
	}
	hash, err := auth.HashPassword(next)
	switch {
	case errors.Is(err, auth.ErrWeakPassword):
		fail("The new password must have at least " + strconv.Itoa(auth.MinPasswordLen) + " characters.")
		return
	case errors.Is(err, auth.ErrLongPassword):
		fail("The new password may have at most " + strconv.Itoa(auth.MaxPasswordLen) + " bytes.")
		return
	case err != nil:
		s.log.Error("hash password", "err", err)
		s.serverError(w, r)
		return
	}
	if err := s.d.Store.SetPassword(ctx, u.ID, hash, false); err != nil {
		s.log.Error("set password", "err", err)
		s.serverError(w, r)
		return
	}
	// Every session of the user, on any device, ends with the old password;
	// this browser gets a fresh one.
	if err := s.d.Store.DeleteUserSessions(ctx, u.ID); err != nil {
		s.log.Error("revoke sessions after password change", "err", err)
		s.serverError(w, r)
		return
	}
	tok, exp, err := s.auth.NewSession(ctx, u.ID)
	if err != nil {
		s.log.Error("new session after password change", "err", err)
		auth.ClearSessionCookie(w, r)
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	auth.SetSessionCookie(w, r, tok, exp, s.now())
	s.audit(r, &u.ID, "user.password", "user:"+u.Login, nil)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// loggedLogin bounds a login name copied into the audit log.
func loggedLogin(login string) string {
	if len(login) > maxLoggedLogin {
		return strings.ToValidUTF8(login[:maxLoggedLogin], "")
	}
	return login
}

// lockedMessage sets Retry-After and returns the lockout message.
func lockedMessage(w http.ResponseWriter, what string, locked *auth.LockedError) string {
	w.Header().Set("Retry-After", strconv.Itoa(int(locked.Wait.Seconds())+1))
	return "Too many failed " + what + ". Try again in " + strconv.Itoa(int(locked.Wait.Minutes())+1) + " min."
}

// audit records an audit entry; a failure is logged, not shown.
func (s *Server) audit(r *http.Request, uid *int64, action, entity string, details map[string]any) {
	var d any
	if details != nil {
		d = details
	}
	if err := s.d.Store.InsertAudit(r.Context(), uid, action, entity, d); err != nil {
		s.log.Error("audit log", "action", action, "err", err)
	}
}
