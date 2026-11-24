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
		w.Header().Set("Retry-After", strconv.Itoa(int(locked.Wait.Seconds())+1))
		s.renderStatus(w, r, http.StatusTooManyRequests, "login", loginData{Next: next, Login: login,
			Error: "Too many failed logins. Try again in " + strconv.Itoa(int(locked.Wait.Minutes())+1) + " min."})
		return
	case errors.Is(err, auth.ErrBadCredentials):
		logged := login
		if len(logged) > maxLoggedLogin {
			logged = strings.ToValidUTF8(logged[:maxLoggedLogin], "")
		}
		s.audit(r, nil, "login.failed", "user:"+logged, map[string]any{"login": logged, "ip": ip})
		s.renderStatus(w, r, http.StatusUnauthorized, "login", loginData{Next: next, Login: login,
			Error: "Invalid login or password."})
		return
	case err != nil:
		s.log.Error("login", "err", err)
		s.serverError(w, r)
		return
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
	su, err := s.d.Store.UserByID(ctx, u.ID)
	if err != nil {
		s.log.Error("load user for password change", "err", err)
		s.serverError(w, r)
		return
	}
	switch {
	case !auth.CheckPassword(su.PasswordHash, cur):
		fail("Current password is incorrect.")
		return
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
	s.audit(r, &u.ID, "user.password", "user:"+u.Login, nil)
	http.Redirect(w, r, "/", http.StatusSeeOther)
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
