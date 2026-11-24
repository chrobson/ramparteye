package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/chrobson/ramparteye/internal/model"
)

// ChangeRun summarises one run on the changes overview.
type ChangeRun struct {
	RunID      int64
	PrevRunID  int64
	Kind       string // scan | import
	Status     string
	StartedAt  *time.Time
	FinishedAt *time.Time
	Applied    bool
	Counts     map[model.ChangeKind]int
	Total      int
}

// InsertChanges stores changes in one statement.
func (s *Store) InsertChanges(ctx context.Context, cs []model.Change) error {
	if len(cs) == 0 {
		return nil
	}
	// COPY cannot cast text to inet, so insert from parallel arrays.
	var (
		run, prev           []int64
		kind, ip, proto, vh []string
		field, old, nw      []string
		port                []int32
	)
	for _, c := range cs {
		run = append(run, c.RunID)
		prev = append(prev, c.PrevRunID)
		kind = append(kind, string(c.Kind))
		ip = append(ip, c.Key.IP.Unmap().String())
		port = append(port, int32(c.Key.Port))
		proto = append(proto, c.Key.Proto)
		vh = append(vh, c.Key.VHost)
		field = append(field, c.Field)
		old = append(old, c.Old)
		nw = append(nw, c.New)
	}
	_, err := s.db.Exec(ctx, `
		INSERT INTO changes (run_id, prev_run_id, kind, ip, port, proto, vhost, field, old, new)
		SELECT r, nullif(p, 0), k, i::inet, po, pr, v, f, o, n
		FROM unnest($1::bigint[], $2::bigint[], $3::text[], $4::text[], $5::int[], $6::text[],
		            $7::text[], $8::text[], $9::text[], $10::text[])
		     AS t(r, p, k, i, po, pr, v, f, o, n)`,
		run, prev, kind, ip, port, proto, vh, field, old, nw)
	return err
}

// Changes returns the changes of one run ordered by asset key.
func (s *Store) Changes(ctx context.Context, runID int64) ([]model.Change, error) {
	rows, err := s.db.Query(ctx, `
		SELECT run_id, coalesce(prev_run_id, 0), kind, host(ip), port, proto, vhost, field, old, new
		FROM changes WHERE run_id = $1 ORDER BY ip, port, proto, vhost, id`, runID)
	if err != nil {
		return nil, err
	}
	return collect(rows, func(r pgx.Rows) (model.Change, error) {
		var c model.Change
		var kind, ip string
		var port int
		if err := r.Scan(&c.RunID, &c.PrevRunID, &kind, &ip, &port, &c.Key.Proto, &c.Key.VHost,
			&c.Field, &c.Old, &c.New); err != nil {
			return c, err
		}
		c.Kind = model.ChangeKind(kind)
		c.Key.Port = uint16(port)
		var err error
		c.Key.IP, err = parseAddr(ip)
		return c, err
	})
}

// ServiceFlips counts, per service key, the new/gone changes recorded in
// the last n diffed scan runs before runID (imports excluded). Keys without
// such a change are absent.
func (s *Store) ServiceFlips(ctx context.Context, runID int64, keys []model.AssetKey, n int) (map[model.AssetKey]int, error) {
	out := map[model.AssetKey]int{}
	if len(keys) == 0 || n <= 0 {
		return out, nil
	}
	var ip, proto, vh []string
	var port []int32
	for _, k := range keys {
		ip = append(ip, k.IP.Unmap().String())
		port = append(port, int32(k.Port))
		proto = append(proto, k.Proto)
		vh = append(vh, k.VHost)
	}
	rows, err := s.db.Query(ctx, `
		WITH runs AS (
			SELECT d.run_id FROM diff_runs d JOIN scan_runs r ON r.id = d.run_id
			WHERE r.kind = 'scan' AND d.run_id < $1
			ORDER BY d.run_id DESC LIMIT $2
		), k AS (
			SELECT i::inet AS ip, po AS port, pr AS proto, v AS vhost
			FROM unnest($3::text[], $4::int[], $5::text[], $6::text[]) AS t(i, po, pr, v)
		)
		SELECT host(c.ip), c.port, c.proto, c.vhost, count(*)
		FROM changes c JOIN k ON c.ip = k.ip AND c.port = k.port AND c.proto = k.proto AND c.vhost = k.vhost
		WHERE c.run_id IN (SELECT run_id FROM runs) AND c.kind IN ('new', 'gone')
		GROUP BY 1, 2, 3, 4`,
		runID, n, ip, port, proto, vh)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var k model.AssetKey
		var a string
		var p, cnt int
		if err := rows.Scan(&a, &p, &k.Proto, &k.VHost, &cnt); err != nil {
			return nil, err
		}
		if k.IP, err = parseAddr(a); err != nil {
			return nil, err
		}
		k.Port = uint16(p)
		out[k] = cnt
	}
	return out, rows.Err()
}

const changeRunCols = `r.id, coalesce(d.prev_run_id, 0), r.kind, r.status, r.started_at, r.finished_at,
	d.run_id IS NOT NULL,
	coalesce((SELECT jsonb_object_agg(kind, n) FROM
		(SELECT kind, count(*) AS n FROM changes c WHERE c.run_id = r.id GROUP BY kind) k), '{}')
	FROM scan_runs r LEFT JOIN diff_runs d ON d.run_id = r.id`

func scanChangeRun(row pgx.Row) (ChangeRun, error) {
	var cr ChangeRun
	var counts []byte
	err := row.Scan(&cr.RunID, &cr.PrevRunID, &cr.Kind, &cr.Status, &cr.StartedAt, &cr.FinishedAt,
		&cr.Applied, &counts)
	if errors.Is(err, pgx.ErrNoRows) {
		return cr, ErrRunNotFound
	}
	if err != nil {
		return cr, err
	}
	raw := map[string]int{}
	if err := json.Unmarshal(counts, &raw); err != nil {
		return cr, err
	}
	cr.Counts = make(map[model.ChangeKind]int, len(raw))
	for k, n := range raw {
		cr.Counts[model.ChangeKind(k)] = n
		cr.Total += n
	}
	return cr, nil
}

// ChangeRuns returns the newest runs with their change counts per kind.
func (s *Store) ChangeRuns(ctx context.Context, limit int) ([]ChangeRun, error) {
	rows, err := s.db.Query(ctx, `SELECT `+changeRunCols+` ORDER BY r.id DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	return collect(rows, func(r pgx.Rows) (ChangeRun, error) { return scanChangeRun(r) })
}

// ChangeRun returns the change summary of one run.
func (s *Store) ChangeRun(ctx context.Context, runID int64) (ChangeRun, error) {
	return scanChangeRun(s.db.QueryRow(ctx, `SELECT `+changeRunCols+` WHERE r.id = $1`, runID))
}
