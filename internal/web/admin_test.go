package web

import (
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"testing"

	"github.com/ctx42/testing/pkg/assert"

	"github.com/chrobson/ramparteye/internal/auth"
	"github.com/chrobson/ramparteye/internal/store"
)

func TestUsersPageNeedsUsersAdmin(t *testing.T) {
	e := newEnv(t)
	c := e.login(t, auth.RoleOperator)

	assert.Equal(t, http.StatusForbidden, e.get("/settings/users", c).Code)
	assert.Equal(t, http.StatusForbidden, e.post("/settings/users", url.Values{"login": {"x"}}, c).Code)
}

func TestUsersPageLists(t *testing.T) {
	e := newEnv(t)
	e.st.addUser(t, "<b>bob</b>", "correct-horse", auth.RoleViewer, false)

	body := e.get("/settings/users", e.login(t, auth.RoleAdmin)).Body.String()

	assert.Contain(t, "&lt;b&gt;bob&lt;/b&gt;", body)
	assert.Contain(t, "Operator", body)
	assert.Contain(t, `name="perm" value="targets.read"`, body)
	assert.NotContain(t, `name="perm" value="settings.admin"`, body)
}

func TestCreateUserGeneratedPassword(t *testing.T) {
	e := newEnv(t)

	rec := e.post("/settings/users", url.Values{"login": {"carol"}, "role": {"Analyst"}}, e.login(t, auth.RoleAdmin))

	assert.Equal(t, http.StatusOK, rec.Code)
	u, err := e.st.UserByLogin(t.Context(), "carol")
	assert.NoError(t, err)
	assert.Equal(t, "Analyst", u.RoleName)
	assert.True(t, u.MustChangePassword)
	m := regexp.MustCompile(`data-password="([^"]+)"`).FindStringSubmatch(rec.Body.String())
	assert.Len(t, 2, m)
	assert.True(t, auth.CheckPassword(u.PasswordHash, m[1]))
	assert.Equal(t, "user.create", e.st.lastAudit().Action)
}

func TestCreateUserTypedPassword(t *testing.T) {
	e := newEnv(t)
	c := e.login(t, auth.RoleAdmin)

	rec := e.post("/settings/users", url.Values{"login": {"dan"}, "role": {"Viewer"}, "password": {"typed-password-1"}}, c)

	assert.Equal(t, http.StatusSeeOther, rec.Code)
	u, _ := e.st.UserByLogin(t.Context(), "dan")
	assert.True(t, auth.CheckPassword(u.PasswordHash, "typed-password-1"))
	assert.True(t, u.MustChangePassword)

	rec = e.post("/settings/users", url.Values{"login": {"eve"}, "role": {"Viewer"}, "password": {"short"}}, c)
	assert.Equal(t, http.StatusUnprocessableEntity, rec.Code)
	assert.Contain(t, "at least 8", rec.Body.String())
	assert.Contain(t, `value="eve"`, rec.Body.String())

	rec = e.post("/settings/users", url.Values{"login": {"dan"}, "role": {"Viewer"}}, c)
	assert.Equal(t, http.StatusUnprocessableEntity, rec.Code)
	assert.Contain(t, "already taken", rec.Body.String())
}

func TestCannotGrantRoleBeyondOwnPerms(t *testing.T) {
	e := newEnv(t)
	id, _ := e.st.CreateRole(t.Context(), "User admins", []string{"users.admin", "results.read"})
	u := e.st.addUser(t, "ua", "correct-horse", "Viewer", false)
	e.st.SetUserRole(t.Context(), u.ID, id)
	c := e.st.session(u.ID)

	rec := e.post("/settings/users", url.Values{"login": {"mallory"}, "role": {"Admin"}, "password": {"typed-password-1"}}, c)

	assert.Equal(t, http.StatusUnprocessableEntity, rec.Code)
	_, err := e.st.UserByLogin(t.Context(), "mallory")
	assert.ErrorIs(t, store.ErrUserNotFound, err)
}

func TestChangeRole(t *testing.T) {
	e := newEnv(t)
	c := e.login(t, auth.RoleAdmin)
	bob := e.st.addUser(t, "bob", "correct-horse", auth.RoleViewer, false)

	rec := e.post("/settings/users/"+strconv.FormatInt(bob.ID, 10)+"/role", url.Values{"role": {"Analyst"}}, c)

	assert.Equal(t, http.StatusSeeOther, rec.Code)
	assert.Equal(t, "Analyst", e.st.user(bob.ID).RoleName)
	assert.Equal(t, "user.role", e.st.lastAudit().Action)
}

func TestCannotChangeOwnRoleOrDisableSelf(t *testing.T) {
	e := newEnv(t)
	me := e.st.addUser(t, "root", "correct-horse", auth.RoleAdmin, false)
	c := e.st.session(me.ID)
	id := strconv.FormatInt(me.ID, 10)

	e.post("/settings/users/"+id+"/role", url.Values{"role": {"Viewer"}}, c)
	e.post("/settings/users/"+id+"/disable", nil, c)

	assert.Equal(t, auth.RoleAdmin, e.st.user(me.ID).RoleName)
	assert.False(t, e.st.user(me.ID).Disabled)
}

func TestDisableUser(t *testing.T) {
	e := newEnv(t)
	c := e.login(t, auth.RoleAdmin)
	bob := e.st.addUser(t, "bob", "correct-horse", auth.RoleViewer, false)
	bobCookie := e.st.session(bob.ID)
	id := strconv.FormatInt(bob.ID, 10)

	rec := e.post("/settings/users/"+id+"/disable", nil, c)

	assert.Equal(t, http.StatusSeeOther, rec.Code)
	assert.True(t, e.st.user(bob.ID).Disabled)
	assert.Equal(t, "user.disable", e.st.lastAudit().Action)
	assert.Equal(t, http.StatusSeeOther, e.get("/", bobCookie).Code) // session no longer works

	e.post("/settings/users/"+id+"/enable", nil, c)
	assert.False(t, e.st.user(bob.ID).Disabled)
	assert.Equal(t, "user.enable", e.st.lastAudit().Action)
}

func TestCreateCustomRole(t *testing.T) {
	e := newEnv(t)
	c := e.login(t, auth.RoleAdmin)

	rec := e.post("/settings/roles", url.Values{"name": {"Auditor"}, "perm": {"results.read", "export"}}, c)

	assert.Equal(t, http.StatusSeeOther, rec.Code)
	assert.Len(t, 1, e.st.admin.roles)
	assert.Equal(t, []string{"results.read", "export"}, e.st.admin.roles[0].Perms)
	assert.Equal(t, "role.create", e.st.lastAudit().Action)
}

func TestCustomRoleNeverGetsSettingsAdmin(t *testing.T) {
	e := newEnv(t)
	c := e.login(t, auth.RoleAdmin)

	rec := e.post("/settings/roles", url.Values{"name": {"Sneaky"}, "perm": {"results.read", "settings.admin"}}, c)
	assert.Equal(t, http.StatusUnprocessableEntity, rec.Code)
	assert.Contain(t, "settings.admin", rec.Body.String())

	rec = e.post("/settings/roles", url.Values{"name": {"Bogus"}, "perm": {"root.everything"}}, c)
	assert.Equal(t, http.StatusUnprocessableEntity, rec.Code)

	rec = e.post("/settings/roles", url.Values{"name": {"Admin"}, "perm": {"results.read"}}, c)
	assert.Equal(t, http.StatusUnprocessableEntity, rec.Code)
	assert.Len(t, 0, e.st.admin.roles)
}

func TestDeleteCustomRole(t *testing.T) {
	e := newEnv(t)
	c := e.login(t, auth.RoleAdmin)
	id, _ := e.st.CreateRole(t.Context(), "Auditor", []string{"results.read"})

	rec := e.post("/settings/roles/"+strconv.FormatInt(id, 10)+"/delete", nil, c)

	assert.Equal(t, http.StatusSeeOther, rec.Code)
	assert.Len(t, 0, e.st.admin.roles)
	assert.Equal(t, "role.delete", e.st.lastAudit().Action)

	rec = e.post("/settings/roles/1/delete", nil, c)
	assert.Equal(t, "Built-in roles cannot be deleted.", flashOf(t, rec))
}

func TestLastAdminCannotBeDemotedOrDisabled(t *testing.T) {
	e := newEnv(t)
	// A user administrator with a custom role holding every permission but
	// settings.admin cannot demote the only Admin either: the store refuses.
	all := []string{"targets.read", "targets.write", "scans.run", "results.read", "results.edit",
		"signatures.write", "export", "users.admin", "settings.admin"}
	rid, _ := e.st.CreateRole(t.Context(), "Root-like", all)
	ua := e.st.addUser(t, "ua", "correct-horse", auth.RoleViewer, false)
	e.st.SetUserRole(t.Context(), ua.ID, rid)
	c := e.st.session(ua.ID)
	root := e.st.addUser(t, "root", "correct-horse", auth.RoleAdmin, false)
	id := strconv.FormatInt(root.ID, 10)

	rec := e.post("/settings/users/"+id+"/role", url.Values{"role": {"Viewer"}}, c)
	assert.Equal(t, http.StatusConflict, rec.Code)
	assert.Contain(t, "last active Admin", rec.Body.String())

	rec = e.post("/settings/users/"+id+"/disable", nil, c)
	assert.Equal(t, http.StatusConflict, rec.Code)
	assert.Equal(t, auth.RoleAdmin, e.st.user(root.ID).RoleName)
	assert.False(t, e.st.user(root.ID).Disabled)
}

func TestDeleteRoleNeedsItsPerms(t *testing.T) {
	e := newEnv(t)
	rid, _ := e.st.CreateRole(t.Context(), "User admins", []string{"users.admin", "results.read"})
	ua := e.st.addUser(t, "ua", "correct-horse", auth.RoleViewer, false)
	e.st.SetUserRole(t.Context(), ua.ID, rid)
	other, _ := e.st.CreateRole(t.Context(), "Scanners", []string{"scans.run"})

	rec := e.post("/settings/roles/"+strconv.FormatInt(other, 10)+"/delete", nil, e.st.session(ua.ID))

	assert.Equal(t, http.StatusSeeOther, rec.Code)
	assert.Contain(t, "scans.run", flashOf(t, rec))
	assert.Len(t, 2, e.st.admin.roles)
}
