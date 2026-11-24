package store

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/chrobson/ramparteye/internal/model"
)

var (
	// ErrUserNotFound is returned for an unknown user or session.
	ErrUserNotFound = fmt.Errorf("user %w", ErrNotFound)
	// ErrLoginTaken is returned when creating a user whose login exists.
	ErrLoginTaken = errors.New("login already taken")
	// ErrRoleNotFound is returned for an unknown role name or id.
	ErrRoleNotFound = fmt.Errorf("role %w", ErrNotFound)
	// ErrRoleInUse is returned when deleting a role that users still have.
	ErrRoleInUse = errors.New("role is assigned to users")
	// ErrRoleBuiltin is returned when deleting a built-in role.
	ErrRoleBuiltin = errors.New("built-in role cannot be deleted")
	// ErrLastAdmin is returned when a change would leave no active Admin.
	ErrLastAdmin = errors.New("the last active Admin cannot be demoted or disabled")
)

// User is a user row joined with its role and permissions.
type User struct {
	ID                 int64
	Login              string
	PasswordHash       string
	RoleID             int64
	RoleName           string
	Perms              []string
	MustChangePassword bool
	// Disabled accounts cannot log in and their sessions are ignored.
	Disabled  bool
	CreatedAt time.Time
}

// Role is a role with its permissions and number of assigned users.
type Role struct {
	ID      int64
	Name    string
	Builtin bool
	Perms   []string
	Users   int
}

const userCols = `u.id, u.login, u.pass_hash, u.role_id, r.name,
	coalesce((SELECT array_agg(rp.perm ORDER BY rp.perm) FROM role_permissions rp WHERE rp.role_id = u.role_id), '{}'),
	u.must_change_password, u.disabled, u.created_at`

func scanUser(row pgx.Row) (User, error) {
	var u User
	err := row.Scan(&u.ID, &u.Login, &u.PasswordHash, &u.RoleID, &u.RoleName, &u.Perms,
		&u.MustChangePassword, &u.Disabled, &u.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return u, ErrUserNotFound
	}
	return u, err
}

// CountUsers returns the number of users.
func (s *Store) CountUsers(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRow(ctx, `SELECT count(*) FROM users`).Scan(&n)
	return n, err
}

// CreateInitialUsers creates every user in one transaction, but only while
// the users table is empty; it reports whether it created them. Concurrent
// first starts are serialised by a table lock, so exactly one of them
// creates the accounts and none is left half-created.
func (s *Store) CreateInitialUsers(ctx context.Context, users []model.NewUser) (bool, error) {
	created := false
	err := s.InTx(ctx, func(tx *Store) error {
		if _, err := tx.db.Exec(ctx, `LOCK TABLE users IN SHARE ROW EXCLUSIVE MODE`); err != nil {
			return err
		}
		n, err := tx.CountUsers(ctx)
		if err != nil || n > 0 {
			return err
		}
		for _, u := range users {
			id, err := tx.CreateUser(ctx, u)
			if err != nil {
				return err
			}
			if err := tx.InsertAudit(ctx, nil, "user.seed", "user:"+u.Login,
				map[string]any{"user_id": id, "role": u.Role}); err != nil {
				return err
			}
		}
		created = true
		return nil
	})
	if err != nil {
		return false, err
	}
	return created, nil
}

// CreateUser inserts a user with the role named u.Role and returns its id.
func (s *Store) CreateUser(ctx context.Context, u model.NewUser) (int64, error) {
	roleID, err := s.RoleIDByName(ctx, u.Role)
	if err != nil {
		return 0, err
	}
	var id int64
	err = s.db.QueryRow(ctx, `INSERT INTO users (login, pass_hash, role_id, must_change_password)
		VALUES ($1, $2, $3, $4) RETURNING id`, u.Login, u.PasswordHash, roleID, u.MustChangePassword).Scan(&id)
	if pgCode(err) == codeUniqueViolation {
		return 0, ErrLoginTaken
	}
	if err != nil {
		return 0, fmt.Errorf("create user: %w", sanitize(err))
	}
	return id, nil
}

// UserByLogin loads a user, password hash included, by login.
func (s *Store) UserByLogin(ctx context.Context, login string) (User, error) {
	return scanUser(s.db.QueryRow(ctx,
		`SELECT `+userCols+` FROM users u JOIN roles r ON r.id = u.role_id WHERE u.login = $1`, login))
}

// UserByID loads a user by id.
func (s *Store) UserByID(ctx context.Context, id int64) (User, error) {
	return scanUser(s.db.QueryRow(ctx,
		`SELECT `+userCols+` FROM users u JOIN roles r ON r.id = u.role_id WHERE u.id = $1`, id))
}

// Users returns all users ordered by login.
func (s *Store) Users(ctx context.Context) ([]User, error) {
	rows, err := s.db.Query(ctx,
		`SELECT `+userCols+` FROM users u JOIN roles r ON r.id = u.role_id ORDER BY u.login`)
	if err != nil {
		return nil, err
	}
	return collect(rows, func(r pgx.Rows) (User, error) { return scanUser(r) })
}

// SetUserRole changes a user's role. It refuses with ErrLastAdmin when the
// user is the last active Admin and the new role is not Admin.
func (s *Store) SetUserRole(ctx context.Context, userID, roleID int64) error {
	return s.InTx(ctx, func(tx *Store) error {
		if err := tx.guardLastAdmin(ctx, userID, `SELECT name = 'Admin' AND builtin FROM roles WHERE id = $1`, roleID); err != nil {
			return err
		}
		tag, err := tx.db.Exec(ctx, `UPDATE users SET role_id = $2 WHERE id = $1`, userID, roleID)
		if pgCode(err) == codeForeignKeyViolation {
			return ErrRoleNotFound
		}
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrUserNotFound
		}
		return nil
	})
}

// SetUserDisabled disables or re-enables an account. Sessions of a
// disabled account stop working at once (SessionUserAt skips them).
// Disabling the last active Admin is refused with ErrLastAdmin.
func (s *Store) SetUserDisabled(ctx context.Context, userID int64, disabled bool) error {
	return s.InTx(ctx, func(tx *Store) error {
		if disabled {
			if err := tx.guardLastAdmin(ctx, userID, `SELECT false`); err != nil {
				return err
			}
		}
		tag, err := tx.db.Exec(ctx, `UPDATE users SET disabled = $2 WHERE id = $1`, userID, disabled)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrUserNotFound
		}
		return nil
	})
}

// guardLastAdmin returns ErrLastAdmin when userID is an active Admin, the
// change leaves it no Admin (stillAdmin, a query over args, is false or
// finds no row) and no other active Admin exists. The active Admin rows
// are locked, so concurrent demotions are serialised and cannot both pass.
func (s *Store) guardLastAdmin(ctx context.Context, userID int64, stillAdmin string, args ...any) error {
	rows, err := s.db.Query(ctx, `SELECT u.id FROM users u JOIN roles r ON r.id = u.role_id
		WHERE r.name = 'Admin' AND r.builtin AND NOT u.disabled FOR UPDATE OF u`)
	if err != nil {
		return err
	}
	ids, err := collect(rows, func(r pgx.Rows) (int64, error) {
		var id int64
		err := r.Scan(&id)
		return id, err
	})
	if err != nil {
		return err
	}
	if !slices.Contains(ids, userID) || len(ids) > 1 {
		return nil
	}
	var keep bool
	err = s.db.QueryRow(ctx, stillAdmin, args...).Scan(&keep)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	if !keep {
		return ErrLastAdmin
	}
	return nil
}

// SetPassword replaces a user's password hash and the forced-change flag.
func (s *Store) SetPassword(ctx context.Context, userID int64, hash string, mustChange bool) error {
	tag, err := s.db.Exec(ctx, `UPDATE users SET pass_hash = $2, must_change_password = $3 WHERE id = $1`,
		userID, hash, mustChange)
	if err != nil {
		return fmt.Errorf("set password: %w", sanitize(err))
	}
	if tag.RowsAffected() == 0 {
		return ErrUserNotFound
	}
	return nil
}

// RoleIDByName resolves a role name.
func (s *Store) RoleIDByName(ctx context.Context, name string) (int64, error) {
	var id int64
	err := s.db.QueryRow(ctx, `SELECT id FROM roles WHERE name = $1`, name).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, fmt.Errorf("%w: %q", ErrRoleNotFound, name)
	}
	return id, err
}

// Roles returns roles with permissions and user counts, built-ins first.
func (s *Store) Roles(ctx context.Context) ([]Role, error) {
	rows, err := s.db.Query(ctx, `SELECT r.id, r.name, r.builtin,
		coalesce((SELECT array_agg(rp.perm ORDER BY rp.perm) FROM role_permissions rp WHERE rp.role_id = r.id), '{}'),
		(SELECT count(*) FROM users u WHERE u.role_id = r.id)
		FROM roles r ORDER BY r.builtin DESC, r.id`)
	if err != nil {
		return nil, err
	}
	return collect(rows, func(row pgx.Rows) (Role, error) {
		var r Role
		err := row.Scan(&r.ID, &r.Name, &r.Builtin, &r.Perms, &r.Users)
		return r, err
	})
}

// CreateRole inserts a custom role with its permissions atomically.
func (s *Store) CreateRole(ctx context.Context, name string, perms []string) (int64, error) {
	var id int64
	err := s.InTx(ctx, func(tx *Store) error {
		if err := tx.db.QueryRow(ctx, `INSERT INTO roles (name, builtin) VALUES ($1, false) RETURNING id`,
			name).Scan(&id); err != nil {
			return err
		}
		_, err := tx.db.Exec(ctx, `INSERT INTO role_permissions (role_id, perm) SELECT $1, unnest($2::text[])`,
			id, nonNilSlice(perms))
		return err
	})
	return id, err
}

// DeleteRole deletes a custom role that no user has and returns its name.
func (s *Store) DeleteRole(ctx context.Context, id int64) (string, error) {
	var (
		name    string
		builtin bool
		users   int
	)
	err := s.db.QueryRow(ctx, `SELECT name, builtin, (SELECT count(*) FROM users WHERE role_id = $1)
		FROM roles WHERE id = $1`, id).Scan(&name, &builtin, &users)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrRoleNotFound
	}
	if err != nil {
		return "", err
	}
	if builtin {
		return name, ErrRoleBuiltin
	}
	if users > 0 {
		return name, ErrRoleInUse
	}
	_, err = s.db.Exec(ctx, `DELETE FROM roles WHERE id = $1 AND NOT builtin`, id)
	if pgCode(err) == codeForeignKeyViolation { // assigned concurrently
		return name, ErrRoleInUse
	}
	return name, err
}
