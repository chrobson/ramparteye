package store

import (
	"context"
	"time"
)

// CreateSession stores the SHA-256 of a session token.
func (s *Store) CreateSession(ctx context.Context, tokenHash []byte, userID int64, expires time.Time) error {
	_, err := s.db.Exec(ctx, `INSERT INTO sessions (token_hash, user_id, expires_at) VALUES ($1, $2, $3)`,
		tokenHash, userID, expires)
	if err != nil {
		return sanitize(err)
	}
	return nil
}

// SessionUser returns the user owning a session that is not expired now, or
// ErrUserNotFound.
func (s *Store) SessionUser(ctx context.Context, tokenHash []byte) (User, error) {
	return s.SessionUserAt(ctx, tokenHash, time.Now())
}

// SessionUserAt is SessionUser with an explicit clock.
func (s *Store) SessionUserAt(ctx context.Context, tokenHash []byte, now time.Time) (User, error) {
	return scanUser(s.db.QueryRow(ctx, `SELECT `+userCols+` FROM sessions s
		JOIN users u ON u.id = s.user_id
		JOIN roles r ON r.id = u.role_id
		WHERE s.token_hash = $1 AND s.expires_at > $2`, tokenHash, now))
}

// DeleteSession removes one session.
func (s *Store) DeleteSession(ctx context.Context, tokenHash []byte) error {
	_, err := s.db.Exec(ctx, `DELETE FROM sessions WHERE token_hash = $1`, tokenHash)
	return err
}

// DeleteUserSessions removes every session of a user (role or password
// change).
func (s *Store) DeleteUserSessions(ctx context.Context, userID int64) error {
	_, err := s.db.Exec(ctx, `DELETE FROM sessions WHERE user_id = $1`, userID)
	return err
}

// DeleteExpiredSessions removes expired sessions and returns how many.
func (s *Store) DeleteExpiredSessions(ctx context.Context) (int64, error) {
	tag, err := s.db.Exec(ctx, `DELETE FROM sessions WHERE expires_at <= now()`)
	return tag.RowsAffected(), err
}
