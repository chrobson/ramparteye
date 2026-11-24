package store

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/chrobson/ramparteye/internal/model"
)

// ErrAnnotationNotFound is returned when no annotation exists for a key.
var ErrAnnotationNotFound = fmt.Errorf("annotation %w", ErrNotFound)

// Annotation is an analyst edit keyed by the natural asset key. It lives
// independently of runs, so it survives rescans. Port 0 = host level.
type Annotation struct {
	Key           model.AssetKey
	Comment       string
	Tags          []string
	Severity      string // "" = not set; otherwise a model.Severity value
	FalsePositive bool
	UpdatedBy     int64 // 0 = unknown
	UpdatedAt     time.Time
}

const annotationCols = `host(ip), port, proto, vhost, comment, tags, coalesce(severity, ''),
	false_positive, coalesce(updated_by, 0), updated_at`

func scanAnnotation(row pgx.Row) (Annotation, error) {
	var a Annotation
	var ip string
	var port int
	err := row.Scan(&ip, &port, &a.Key.Proto, &a.Key.VHost, &a.Comment, &a.Tags, &a.Severity,
		&a.FalsePositive, &a.UpdatedBy, &a.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return a, ErrAnnotationNotFound
	}
	if err != nil {
		return a, err
	}
	a.Key.Port = uint16(port)
	a.Tags = nonNilSlice(a.Tags)
	a.Key.IP, err = parseAddr(ip)
	return a, err
}

func keyArgs(k model.AssetKey) []any {
	return []any{k.IP.Unmap().String(), int(k.Port), k.Proto, k.VHost}
}

const keyMatch = `ip = $1::inet AND port = $2 AND proto = $3 AND vhost = $4`

// Annotation returns the annotation of a key.
func (s *Store) Annotation(ctx context.Context, k model.AssetKey) (Annotation, error) {
	return scanAnnotation(s.db.QueryRow(ctx, `SELECT `+annotationCols+` FROM annotations WHERE `+keyMatch,
		keyArgs(k)...))
}

// Annotations returns every annotation, or those of one host when ip is
// valid.
func (s *Store) Annotations(ctx context.Context, ip netip.Addr) ([]Annotation, error) {
	var ipArg *string // NULL = every host; avoids casting '' to inet
	if ip.IsValid() {
		v := ip.Unmap().String()
		ipArg = &v
	}
	rows, err := s.db.Query(ctx, `SELECT `+annotationCols+` FROM annotations
		WHERE $1::inet IS NULL OR ip = $1::inet ORDER BY ip, port, proto, vhost`, ipArg)
	if err != nil {
		return nil, err
	}
	return collect(rows, func(r pgx.Rows) (Annotation, error) { return scanAnnotation(r) })
}

// AnnotationsByIPs returns the annotations of the given hosts (all ports)
// keyed by asset key.
func (s *Store) AnnotationsByIPs(ctx context.Context, ips []netip.Addr) (map[model.AssetKey]Annotation, error) {
	out := map[model.AssetKey]Annotation{}
	if len(ips) == 0 {
		return out, nil
	}
	strs := make([]string, len(ips))
	for i, ip := range ips {
		strs[i] = ip.Unmap().String()
	}
	rows, err := s.db.Query(ctx, `SELECT `+annotationCols+` FROM annotations WHERE ip = ANY($1::inet[])`, strs)
	if err != nil {
		return nil, err
	}
	list, err := collect(rows, func(r pgx.Rows) (Annotation, error) { return scanAnnotation(r) })
	for _, a := range list {
		out[a.Key] = a
	}
	return out, err
}

// UpsertAnnotation creates or replaces the annotation of a.Key and writes
// an audit entry.
func (s *Store) UpsertAnnotation(ctx context.Context, a Annotation) (Annotation, error) {
	var out Annotation
	err := s.InTx(ctx, func(tx *Store) error {
		var err error
		out, err = scanAnnotation(tx.db.QueryRow(ctx, `
			INSERT INTO annotations (ip, port, proto, vhost, comment, tags, severity, false_positive,
				updated_by, updated_at)
			VALUES ($1::inet, $2, $3, $4, $5, $6, nullif($7, ''), $8, nullif($9::bigint, 0), now())
			ON CONFLICT (ip, port, proto, vhost) DO UPDATE SET
				comment = EXCLUDED.comment, tags = EXCLUDED.tags, severity = EXCLUDED.severity,
				false_positive = EXCLUDED.false_positive, updated_by = EXCLUDED.updated_by,
				updated_at = EXCLUDED.updated_at
			RETURNING `+annotationCols,
			append(keyArgs(a.Key), a.Comment, nonNilSlice(a.Tags), a.Severity, a.FalsePositive, a.UpdatedBy)...))
		if err != nil {
			return err
		}
		return tx.annotationAudit(ctx, "annotation.upsert", a.UpdatedBy, a.Key)
	})
	return out, err
}

// DeleteAnnotation removes the annotation of k and writes an audit entry.
func (s *Store) DeleteAnnotation(ctx context.Context, k model.AssetKey, userID int64) error {
	return s.InTx(ctx, func(tx *Store) error {
		tag, err := tx.db.Exec(ctx, `DELETE FROM annotations WHERE `+keyMatch, keyArgs(k)...)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrAnnotationNotFound
		}
		return tx.annotationAudit(ctx, "annotation.delete", userID, k)
	})
}

func (s *Store) annotationAudit(ctx context.Context, action string, userID int64, k model.AssetKey) error {
	var uid *int64
	if userID != 0 {
		uid = &userID
	}
	return s.InsertAudit(ctx, uid, action, "annotation", map[string]any{
		"ip": k.IP.Unmap().String(), "port": k.Port, "proto": k.Proto, "vhost": k.VHost,
	})
}
