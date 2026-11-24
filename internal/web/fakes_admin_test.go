package web

import (
	"context"
	"slices"
	"sort"
	"time"

	"github.com/chrobson/ramparteye/internal/auth"
	"github.com/chrobson/ramparteye/internal/dojo"
	"github.com/chrobson/ramparteye/internal/model"
	"github.com/chrobson/ramparteye/internal/store"
)

// adminData is what the fake store keeps for signatures and settings.
type adminData struct {
	history  []store.ObservedService
	roles    []store.Role // custom roles; built-ins are derived from auth.BuiltinRoles
	nextRole int64
	dojo     *store.DojoConfig
	pushes   []store.DojoPush
	// auditFull makes AuditQuery return a full page at any offset.
	auditFull bool
}

// fakeChecker is a DefectDojo client with a fixed Check result.
type fakeChecker struct {
	res      dojo.CheckResult
	err      error
	token    string        // token of the settings the client was built for
	product  string        // product passed to Check
	deadline time.Duration // time left on the Check context
}

func (f *fakeChecker) Check(ctx context.Context, product string) (dojo.CheckResult, error) {
	f.product = product
	if dl, ok := ctx.Deadline(); ok {
		f.deadline = time.Until(dl)
	}
	return f.res, f.err
}

func (f *fakeStore) Signature(_ context.Context, id string) (store.SignatureRow, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, r := range f.assets.sigs {
		if r.ID == id {
			return r, nil
		}
	}
	return store.SignatureRow{}, store.ErrSignatureNotFound
}

func (f *fakeStore) SyncBuiltinSignatures(context.Context, []store.SignatureRow) ([]string, error) {
	return nil, nil
}

func (f *fakeStore) CreateCustomSignature(_ context.Context, row store.SignatureRow) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, r := range f.assets.sigs {
		if r.ID == row.ID {
			return store.ErrSignatureExists
		}
	}
	f.assets.sigs = append(f.assets.sigs, row)
	return nil
}

func (f *fakeStore) UpdateCustomSignature(_ context.Context, id string, row store.SignatureRow) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i, r := range f.assets.sigs {
		if r.ID == id {
			if r.IsBuiltin() {
				return store.ErrSignatureBuiltin
			}
			f.assets.sigs[i].Name, f.assets.sigs[i].YAML, f.assets.sigs[i].PathProbe = row.Name, row.YAML, row.PathProbe
			return nil
		}
	}
	return store.ErrSignatureNotFound
}

func (f *fakeStore) SetSignatureEnabled(_ context.Context, id string, enabled bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i, r := range f.assets.sigs {
		if r.ID == id {
			f.assets.sigs[i].Enabled = enabled
			return nil
		}
	}
	return store.ErrSignatureNotFound
}

func (f *fakeStore) DeleteCustomSignature(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i, r := range f.assets.sigs {
		if r.ID == id {
			if r.IsBuiltin() {
				return store.ErrSignatureBuiltin
			}
			f.assets.sigs = slices.Delete(f.assets.sigs, i, i+1)
			return nil
		}
	}
	return store.ErrSignatureNotFound
}

func (f *fakeStore) sig(id string) (store.SignatureRow, bool) {
	r, err := f.Signature(context.Background(), id)
	return r, err == nil
}

func (f *fakeStore) BacktestHistory(context.Context, int) ([]store.ObservedService, error) {
	return f.admin.history, nil
}

// builtinRoleIDs gives the built-in roles fixed ids 1-4.
var builtinRoleIDs = map[string]int64{auth.RoleAdmin: 1, auth.RoleOperator: 2, auth.RoleAnalyst: 3, auth.RoleViewer: 4}

func (f *fakeStore) allRoles() []store.Role {
	var out []store.Role
	for _, name := range []string{auth.RoleAdmin, auth.RoleOperator, auth.RoleAnalyst, auth.RoleViewer} {
		var perms []string
		for _, p := range auth.BuiltinRoles[name] {
			perms = append(perms, string(p))
		}
		sort.Strings(perms)
		out = append(out, store.Role{ID: builtinRoleIDs[name], Name: name, Builtin: true, Perms: perms})
	}
	out = append(out, f.admin.roles...)
	for i := range out {
		for _, u := range f.users {
			if u.RoleName == out[i].Name {
				out[i].Users++
			}
		}
	}
	return out
}

func (f *fakeStore) Roles(context.Context) ([]store.Role, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.allRoles(), nil
}

func (f *fakeStore) CreateRole(_ context.Context, name string, perms []string) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.admin.nextRole++
	id := 100 + f.admin.nextRole
	f.admin.roles = append(f.admin.roles, store.Role{ID: id, Name: name, Perms: perms})
	return id, nil
}

func (f *fakeStore) DeleteRole(_ context.Context, id int64) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, r := range f.allRoles() {
		if r.ID != id {
			continue
		}
		switch {
		case r.Builtin:
			return r.Name, store.ErrRoleBuiltin
		case r.Users > 0:
			return r.Name, store.ErrRoleInUse
		}
		f.admin.roles = slices.DeleteFunc(f.admin.roles, func(x store.Role) bool { return x.ID == id })
		return r.Name, nil
	}
	return "", store.ErrRoleNotFound
}

func (f *fakeStore) roleByID(id int64) (store.Role, bool) {
	for _, r := range f.allRoles() {
		if r.ID == id {
			return r, true
		}
	}
	return store.Role{}, false
}

func (f *fakeStore) Users(context.Context) ([]store.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []store.User
	for _, u := range f.users {
		out = append(out, *u)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Login < out[j].Login })
	return out, nil
}

func (f *fakeStore) CreateUser(_ context.Context, nu model.NewUser) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, u := range f.users {
		if u.Login == nu.Login {
			return 0, store.ErrLoginTaken
		}
	}
	var role store.Role
	found := false
	for _, r := range f.allRoles() {
		if r.Name == nu.Role {
			role, found = r, true
		}
	}
	if !found {
		return 0, store.ErrRoleNotFound
	}
	f.nextID++
	f.users[f.nextID] = &store.User{ID: f.nextID, Login: nu.Login, PasswordHash: nu.PasswordHash,
		RoleID: role.ID, RoleName: role.Name, Perms: role.Perms, MustChangePassword: nu.MustChangePassword}
	return f.nextID, nil
}

func (f *fakeStore) SetUserRole(_ context.Context, userID, roleID int64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	u, ok := f.users[userID]
	if !ok {
		return store.ErrUserNotFound
	}
	r, ok := f.roleByID(roleID)
	if !ok {
		return store.ErrRoleNotFound
	}
	if r.Name != auth.RoleAdmin && f.lastAdmin(u) {
		return store.ErrLastAdmin
	}
	u.RoleID, u.RoleName, u.Perms = r.ID, r.Name, r.Perms
	return nil
}

func (f *fakeStore) SetUserDisabled(_ context.Context, userID int64, disabled bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	u, ok := f.users[userID]
	if !ok {
		return store.ErrUserNotFound
	}
	if disabled && f.lastAdmin(u) {
		return store.ErrLastAdmin
	}
	u.Disabled = disabled
	return nil
}

// lastAdmin reports whether u is the only active Admin (mirrors the store).
func (f *fakeStore) lastAdmin(u *store.User) bool {
	if u.RoleName != auth.RoleAdmin || u.Disabled {
		return false
	}
	for _, o := range f.users {
		if o.ID != u.ID && o.RoleName == auth.RoleAdmin && !o.Disabled {
			return false
		}
	}
	return true
}

func (f *fakeStore) AuditQuery(_ context.Context, q store.AuditFilter) ([]store.AuditEntry, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var all []store.AuditEntry
	for i := len(f.audit) - 1; i >= 0; i-- {
		a := f.audit[i]
		if q.Action != "" && a.Action != q.Action {
			continue
		}
		e := store.AuditEntry{ID: int64(i + 1), At: testNow, UserID: a.UserID, Action: a.Action, Entity: a.Entity,
			Details: "{}"}
		if s, ok := a.Details.(string); ok {
			e.Details = s
		}
		if a.UserID != nil {
			if u, ok := f.users[*a.UserID]; ok {
				e.Login = u.Login
			}
		}
		all = append(all, e)
	}
	if f.admin.auditFull {
		for len(all) < q.Limit {
			all = append(all, store.AuditEntry{Action: "pad", Details: "{}"})
		}
		q.Offset = 0
	}
	if q.Offset >= len(all) {
		return nil, nil
	}
	all = all[q.Offset:]
	if len(all) > q.Limit {
		all = all[:q.Limit]
	}
	return all, nil
}

func (f *fakeStore) AuditActions(context.Context) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, a := range f.audit {
		if !slices.Contains(out, a.Action) {
			out = append(out, a.Action)
		}
	}
	sort.Strings(out)
	return out, nil
}

func (f *fakeStore) DojoConfig(context.Context) (store.DojoConfig, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.admin.dojo == nil {
		return store.DojoConfig{}, store.ErrNotFound
	}
	return *f.admin.dojo, nil
}

func (f *fakeStore) SaveDojoConfig(_ context.Context, c store.DojoConfig) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.admin.dojo != nil && c.TokenEnc == nil && !c.ClearToken {
		c.TokenEnc = f.admin.dojo.TokenEnc
	}
	c.ClearToken = false
	f.admin.dojo = &c
	return nil
}

func (f *fakeStore) DojoPushes(context.Context, int) ([]store.DojoPush, error) {
	return f.admin.pushes, nil
}
