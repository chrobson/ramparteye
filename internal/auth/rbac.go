package auth

import (
	"context"
	"slices"
)

// Perm is a permission name stored in role_permissions.perm.
type Perm string

// The fixed permission list.
const (
	PermTargetsRead     Perm = "targets.read"
	PermTargetsWrite    Perm = "targets.write"
	PermScansRun        Perm = "scans.run"
	PermResultsRead     Perm = "results.read"
	PermResultsEdit     Perm = "results.edit"
	PermSignaturesWrite Perm = "signatures.write"
	PermExport          Perm = "export"
	PermUsersAdmin      Perm = "users.admin"
	PermSettingsAdmin   Perm = "settings.admin"
)

// AllPerms is the ordered, fixed list of permissions.
var AllPerms = []Perm{
	PermTargetsRead, PermTargetsWrite, PermScansRun, PermResultsRead,
	PermResultsEdit, PermSignaturesWrite, PermExport, PermUsersAdmin,
	PermSettingsAdmin,
}

// ValidPerm reports whether p is on the fixed permission list.
func ValidPerm(p string) bool { return slices.Contains(AllPerms, Perm(p)) }

// Built-in role names (seeded by migration 0002_roles.sql).
const (
	RoleAdmin    = "Admin"
	RoleOperator = "Operator"
	RoleAnalyst  = "Analyst"
	RoleViewer   = "Viewer"
)

// BuiltinRoles mirrors the permissions inserted by migration 0002_roles.sql.
var BuiltinRoles = map[string][]Perm{
	RoleAdmin: AllPerms,
	RoleOperator: {PermTargetsRead, PermTargetsWrite, PermScansRun, PermResultsRead,
		PermResultsEdit, PermSignaturesWrite, PermExport},
	RoleAnalyst: {PermTargetsRead, PermResultsRead, PermResultsEdit, PermExport},
	RoleViewer:  {PermTargetsRead, PermResultsRead},
}

// User is the authenticated principal stored in the request context.
type User struct {
	ID                 int64
	Login              string
	RoleName           string
	Perms              []Perm
	MustChangePassword bool
}

// Can reports whether the user holds perm.
func (u User) Can(perm Perm) bool { return slices.Contains(u.Perms, perm) }

type userKey struct{}

// WithUser returns a context carrying u.
func WithUser(ctx context.Context, u User) context.Context {
	return context.WithValue(ctx, userKey{}, u)
}

// CurrentUser returns the authenticated user, if any.
func CurrentUser(ctx context.Context) (User, bool) {
	u, ok := ctx.Value(userKey{}).(User)
	return u, ok
}

// Can reports whether the context's user holds perm. No user can do nothing.
func Can(ctx context.Context, perm Perm) bool {
	u, ok := CurrentUser(ctx)
	return ok && u.Can(perm)
}
