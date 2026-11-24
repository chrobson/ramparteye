package web

import (
	"crypto/rand"
	"errors"
	"math/big"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/go-chi/chi/v5"

	"github.com/chrobson/ramparteye/internal/auth"
	"github.com/chrobson/ramparteye/internal/model"
	"github.com/chrobson/ramparteye/internal/store"
)

// Account and role limits.
const (
	maxRoleName       = 64 // runes
	generatedPassword = 16 // characters
	passwordAlphabet  = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
)

// UsersData is the Users & roles tab.
type UsersData struct {
	Tabs      []SettingsTab
	Users     []UserRow
	Roles     []store.Role
	Perms     []auth.Perm // permissions a custom role may hold
	Error     string
	Login     string // submitted create form
	Role      string
	RoleName  string // submitted role form
	RolePerms []string
	Created   string // login of a user created with a generated password
	Password  string // that password, shown once
}

// UserRow is a user on the list.
type UserRow struct {
	store.User
	Self bool
}

// customRolePerms are the permissions a custom role may hold:
// settings.admin stays with the built-in Admin role.
var customRolePerms = slices.DeleteFunc(slices.Clone(auth.AllPerms),
	func(p auth.Perm) bool { return p == auth.PermSettingsAdmin })

func (s *Server) usersPage(w http.ResponseWriter, r *http.Request) {
	s.renderUsers(w, r, http.StatusOK, UsersData{})
}

func (s *Server) renderUsers(w http.ResponseWriter, r *http.Request, status int, d UsersData) {
	ctx := r.Context()
	me, _ := auth.CurrentUser(ctx)
	users, err := s.d.Store.Users(ctx)
	if err == nil {
		d.Roles, err = s.d.Store.Roles(ctx)
	}
	if err != nil {
		s.log.Error("users page", "err", err)
		s.serverError(w, r)
		return
	}
	d.Tabs, d.Perms = tabs(r, "/settings/users"), customRolePerms
	if d.Role == "" {
		d.Role = auth.RoleViewer // least privilege by default
	}
	for _, u := range users {
		u.PasswordHash = ""
		d.Users = append(d.Users, UserRow{User: u, Self: u.ID == me.ID})
	}
	s.renderStatus(w, r, status, "settings-users", d)
}

// grantable finds the role named name and checks that the acting user
// holds every permission of it, so nobody hands out more than they have.
func (s *Server) grantable(r *http.Request, name string) (store.Role, string) {
	roles, err := s.d.Store.Roles(r.Context())
	if err != nil {
		return store.Role{}, "The roles could not be loaded."
	}
	me, _ := auth.CurrentUser(r.Context())
	for _, ro := range roles {
		if ro.Name != name {
			continue
		}
		for _, p := range ro.Perms {
			if !me.Can(auth.Perm(p)) {
				return ro, "You cannot assign the role " + name + ": it includes " + p + ", which your role lacks."
			}
		}
		return ro, ""
	}
	return store.Role{}, "Choose an existing role."
}

func (s *Server) userCreate(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	if err := r.ParseForm(); err != nil {
		s.renderUsers(w, r, http.StatusBadRequest, UsersData{Error: "The form could not be read."})
		return
	}
	login := strings.TrimSpace(r.PostForm.Get("login"))
	roleName := r.PostForm.Get("role")
	password := r.PostForm.Get("password")
	fail := func(msg string) {
		s.renderUsers(w, r, http.StatusUnprocessableEntity, UsersData{Error: msg, Login: login, Role: roleName})
	}
	if msg := checkLogin(login); msg != "" {
		fail(msg)
		return
	}
	role, msg := s.grantable(r, roleName)
	if msg != "" {
		fail(msg)
		return
	}
	generated := password == ""
	if generated {
		var err error
		if password, err = newPassword(); err != nil {
			s.log.Error("generate password", "err", err)
			s.serverError(w, r)
			return
		}
	}
	hash, err := auth.HashPassword(password)
	switch {
	case errors.Is(err, auth.ErrWeakPassword):
		fail("The password must be at least 8 bytes long.")
		return
	case errors.Is(err, auth.ErrLongPassword):
		fail("The password may be at most 72 bytes long.")
		return
	case err != nil:
		s.log.Error("hash password", "err", err)
		s.serverError(w, r)
		return
	}
	id, err := s.d.Store.CreateUser(r.Context(), model.NewUser{Login: login, PasswordHash: hash, Role: role.Name,
		MustChangePassword: true})
	switch {
	case errors.Is(err, store.ErrLoginTaken):
		fail("The login " + login + " is already taken.")
		return
	case errors.Is(err, store.ErrRoleNotFound):
		fail("Choose an existing role.")
		return
	case err != nil:
		s.log.Error("create user", "err", err)
		s.serverError(w, r)
		return
	}
	me, _ := auth.CurrentUser(r.Context())
	s.audit(r, &me.ID, "user.create", "user:"+login, map[string]any{"user_id": id, "role": role.Name,
		"generated_password": generated})
	if generated {
		// Shown once on this response; never stored in a cookie or the log.
		w.Header().Set("Cache-Control", "no-store")
		s.renderUsers(w, r, http.StatusOK, UsersData{Created: login, Password: password})
		return
	}
	setFlash(w, r, "User "+login+" created. They must change the password at the first login.")
	http.Redirect(w, r, "/settings/users", http.StatusSeeOther)
}

func checkLogin(login string) string {
	switch {
	case login == "":
		return "Enter a login."
	case len(login) > auth.MaxLoginLen:
		return "The login may be at most " + strconv.Itoa(auth.MaxLoginLen) + " bytes long."
	case strings.IndexFunc(login, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0:
		return "The login must not contain spaces or control characters."
	}
	return ""
}

func newPassword() (string, error) {
	max := big.NewInt(int64(len(passwordAlphabet)))
	b := make([]byte, generatedPassword)
	for i := range b {
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", err
		}
		b[i] = passwordAlphabet[n.Int64()]
	}
	return string(b), nil
}

// targetUser loads the {id} user for a change by someone else; self
// changes are refused (an admin cannot lock themselves out).
func (s *Server) targetUser(w http.ResponseWriter, r *http.Request, what string) (store.User, bool) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		s.notFound(w, r)
		return store.User{}, false
	}
	u, err := s.d.Store.UserByID(r.Context(), id)
	switch {
	case errors.Is(err, store.ErrUserNotFound):
		s.notFound(w, r)
		return u, false
	case err != nil:
		s.log.Error("load user", "err", err)
		s.serverError(w, r)
		return u, false
	}
	if me, _ := auth.CurrentUser(r.Context()); me.ID == u.ID {
		setFlash(w, r, "You cannot "+what+" your own account.")
		http.Redirect(w, r, "/settings/users", http.StatusSeeOther)
		return u, false
	}
	return u, true
}

func (s *Server) userRole(w http.ResponseWriter, r *http.Request) {
	u, ok := s.targetUser(w, r, "change the role of")
	if !ok {
		return
	}
	role, msg := s.grantable(r, r.PostFormValue("role"))
	if msg == "" && !s.canManage(r, u) {
		msg = "You cannot change the role of " + u.Login + ": their role has permissions yours lacks."
	}
	if msg != "" {
		setFlash(w, r, msg)
		http.Redirect(w, r, "/settings/users", http.StatusSeeOther)
		return
	}
	if err := s.d.Store.SetUserRole(r.Context(), u.ID, role.ID); err != nil {
		s.log.Error("set user role", "err", err)
		s.serverError(w, r)
		return
	}
	me, _ := auth.CurrentUser(r.Context())
	s.audit(r, &me.ID, "user.role", "user:"+u.Login, map[string]any{"user_id": u.ID, "old_role": u.RoleName,
		"new_role": role.Name})
	setFlash(w, r, "Role of "+u.Login+" changed to "+role.Name+".")
	http.Redirect(w, r, "/settings/users", http.StatusSeeOther)
}

// canManage reports whether the acting user holds every permission of u,
// so a user administrator cannot demote or disable a more powerful user.
func (s *Server) canManage(r *http.Request, u store.User) bool {
	me, _ := auth.CurrentUser(r.Context())
	for _, p := range u.Perms {
		if !me.Can(auth.Perm(p)) {
			return false
		}
	}
	return true
}

func (s *Server) userDisable(w http.ResponseWriter, r *http.Request) { s.setDisabled(w, r, true) }

func (s *Server) userEnable(w http.ResponseWriter, r *http.Request) { s.setDisabled(w, r, false) }

func (s *Server) setDisabled(w http.ResponseWriter, r *http.Request, disabled bool) {
	verb, action := "enable", "user.enable"
	if disabled {
		verb, action = "disable", "user.disable"
	}
	u, ok := s.targetUser(w, r, verb)
	if !ok {
		return
	}
	if !s.canManage(r, u) {
		setFlash(w, r, "You cannot "+verb+" "+u.Login+": their role has permissions yours lacks.")
		http.Redirect(w, r, "/settings/users", http.StatusSeeOther)
		return
	}
	ctx := r.Context()
	if err := s.d.Store.SetUserDisabled(ctx, u.ID, disabled); err != nil {
		s.log.Error("set user disabled", "err", err)
		s.serverError(w, r)
		return
	}
	if disabled {
		if err := s.d.Store.DeleteUserSessions(ctx, u.ID); err != nil {
			s.log.Warn("delete sessions of disabled user", "err", err)
		}
	}
	me, _ := auth.CurrentUser(ctx)
	s.audit(r, &me.ID, action, "user:"+u.Login, map[string]any{"user_id": u.ID})
	setFlash(w, r, "User "+u.Login+" "+verb+"d.")
	http.Redirect(w, r, "/settings/users", http.StatusSeeOther)
}

func (s *Server) roleCreate(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	if err := r.ParseForm(); err != nil {
		s.renderUsers(w, r, http.StatusBadRequest, UsersData{Error: "The form could not be read."})
		return
	}
	name := strings.TrimSpace(r.PostForm.Get("name"))
	perms := r.PostForm["perm"]
	fail := func(msg string) {
		s.renderUsers(w, r, http.StatusUnprocessableEntity, UsersData{Error: msg, RoleName: name, RolePerms: perms})
	}
	if msg := s.checkRole(r, name, perms); msg != "" {
		fail(msg)
		return
	}
	var clean []string
	for _, p := range perms {
		if !slices.Contains(clean, p) {
			clean = append(clean, p)
		}
	}
	id, err := s.d.Store.CreateRole(r.Context(), name, clean)
	if err != nil {
		// The name check above ran first; a failure here is a concurrent
		// duplicate or a storage error.
		s.log.Error("create role", "err", err)
		fail("The role could not be created; a role with this name may already exist.")
		return
	}
	me, _ := auth.CurrentUser(r.Context())
	s.audit(r, &me.ID, "role.create", "role:"+name, map[string]any{"role_id": id, "perms": clean})
	setFlash(w, r, "Role "+name+" created.")
	http.Redirect(w, r, "/settings/users", http.StatusSeeOther)
}

// checkRole validates a custom role: a free name, at least one permission,
// only known permissions, never settings.admin, and nothing the acting
// user does not hold.
func (s *Server) checkRole(r *http.Request, name string, perms []string) string {
	switch {
	case name == "":
		return "Enter a role name."
	case utf8.RuneCountInString(name) > maxRoleName:
		return "The role name may be at most " + strconv.Itoa(maxRoleName) + " characters long."
	case len(perms) == 0:
		return "Choose at least one permission."
	}
	me, _ := auth.CurrentUser(r.Context())
	for _, p := range perms {
		switch {
		case !auth.ValidPerm(p):
			return "Unknown permission."
		case auth.Perm(p) == auth.PermSettingsAdmin:
			return "settings.admin belongs to the built-in Admin role only."
		case !me.Can(auth.Perm(p)):
			return "You cannot grant " + p + ": your role lacks it."
		}
	}
	roles, err := s.d.Store.Roles(r.Context())
	if err != nil {
		return "The roles could not be loaded."
	}
	for _, ro := range roles {
		if strings.EqualFold(ro.Name, name) {
			return "A role named " + ro.Name + " already exists."
		}
	}
	return ""
}

func (s *Server) roleDelete(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		s.notFound(w, r)
		return
	}
	name, err := s.d.Store.DeleteRole(r.Context(), id)
	msg := "Role " + name + " deleted."
	switch {
	case errors.Is(err, store.ErrRoleNotFound):
		s.notFound(w, r)
		return
	case errors.Is(err, store.ErrRoleBuiltin):
		msg = "Built-in roles cannot be deleted."
	case errors.Is(err, store.ErrRoleInUse):
		msg = "Role " + name + " is still assigned to users; change their role first."
	case err != nil:
		s.log.Error("delete role", "err", err)
		s.serverError(w, r)
		return
	default:
		me, _ := auth.CurrentUser(r.Context())
		s.audit(r, &me.ID, "role.delete", "role:"+name, map[string]any{"role_id": id})
	}
	setFlash(w, r, msg)
	http.Redirect(w, r, "/settings/users", http.StatusSeeOther)
}
