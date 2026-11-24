package store

// Read-only history views over finished scan runs: change timeline,
// per-asset presence and per-asset history. Imports never count: they hold
// only the hosts of their file.

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/chrobson/ramparteye/internal/model"
)

// lastScanRuns is a CTE body selecting the newest $1 finished scan runs.
const lastScanRuns = `SELECT id, coalesce(started_at, finished_at, 'epoch'::timestamptz) AS started_at
	FROM scan_runs WHERE kind = 'scan' AND status = 'done' ORDER BY id DESC LIMIT $1`

// maxHistoryChanges caps the change list of one asset.
const maxHistoryChanges = 500

// covers is a SQL predicate: run r has a done chunk containing address col.
func covers(col string) string {
	return `EXISTS (SELECT 1 FROM scan_chunks c WHERE c.run_id = r.id AND c.status = 'done' AND c.cidr >>= ` + col + `)`
}

// RunPoint summarises one finished scan run for the change timeline.
type RunPoint struct {
	RunID      int64
	StartedAt  time.Time
	FinishedAt time.Time
	HostsUp    int
	Services   int
	Counts     map[model.ChangeKind]int
}

// Presence is one covering run of an asset and whether the asset was seen.
type Presence struct {
	RunID     int64
	StartedAt time.Time
	Seen      bool
}

// AssetPresence lists the covering runs of one asset, oldest first.
type AssetPresence struct {
	Key     model.AssetKey
	Samples []Presence
}

// AssetRun is one finished scan run as seen from one asset.
type AssetRun struct {
	RunID      int64
	StartedAt  time.Time
	Covered    bool // a done chunk of the run contains the address
	Seen       bool
	Product    string
	Version    string
	HTTPStatus int
	HTTPTitle  string
}

// AssetTimeline is the per-run history and the recorded changes of a key.
type AssetTimeline struct {
	Key     model.AssetKey
	Runs    []AssetRun // oldest first
	Changes []model.Change
}

// RunSeries returns the newest limit finished scan runs, oldest first.
func (s *Store) RunSeries(ctx context.Context, limit int) ([]RunPoint, error) {
	rows, err := s.db.Query(ctx, `
		WITH r AS (SELECT id, started_at, finished_at FROM scan_runs
		           WHERE kind = 'scan' AND status = 'done' ORDER BY id DESC LIMIT $1)
		SELECT r.id, coalesce(r.started_at, r.finished_at, 'epoch'::timestamptz),
		       coalesce(r.finished_at, r.started_at, 'epoch'::timestamptz),
		       (SELECT count(*) FROM host_obs h WHERE h.run_id = r.id AND h.up),
		       (SELECT count(*) FROM services s WHERE s.run_id = r.id),
		       coalesce((SELECT jsonb_object_agg(kind, n) FROM
		           (SELECT kind, count(*) AS n FROM changes c WHERE c.run_id = r.id GROUP BY kind) k), '{}')
		FROM r ORDER BY r.id`, limit)
	if err != nil {
		return nil, err
	}
	return collect(rows, func(r pgx.Rows) (RunPoint, error) {
		var p RunPoint
		var counts []byte
		if err := r.Scan(&p.RunID, &p.StartedAt, &p.FinishedAt, &p.HostsUp, &p.Services, &counts); err != nil {
			return p, err
		}
		raw := map[string]int{}
		if err := json.Unmarshal(counts, &raw); err != nil {
			return p, err
		}
		p.Counts = make(map[model.ChangeKind]int, len(raw))
		for k, n := range raw {
			p.Counts[model.ChangeKind(k)] = n
		}
		return p, nil
	})
}

// HostPresence returns, for every known host, the newest lastRuns finished
// scan runs that covered it and whether it answered. Hosts no such run
// covered are omitted.
func (s *Store) HostPresence(ctx context.Context, lastRuns int) ([]AssetPresence, error) {
	rows, err := s.db.Query(ctx, `
		WITH r AS (`+lastScanRuns+`)
		SELECT host(hs.ip), 0, '', '', r.id, r.started_at, coalesce(h.up, false)
		FROM host_state hs CROSS JOIN r
		LEFT JOIN host_obs h ON h.run_id = r.id AND h.ip = hs.ip
		WHERE `+covers("hs.ip")+`
		ORDER BY hs.ip, r.id`, lastRuns)
	if err != nil {
		return nil, err
	}
	return scanPresence(rows)
}

// ServicePresence is HostPresence for every service key observed in at
// least one of the newest lastRuns finished scan runs.
func (s *Store) ServicePresence(ctx context.Context, lastRuns int) ([]AssetPresence, error) {
	rows, err := s.db.Query(ctx, `
		WITH r AS (`+lastScanRuns+`),
		k AS (SELECT DISTINCT ip, port, proto, vhost FROM services WHERE run_id IN (SELECT id FROM r))
		SELECT host(k.ip), k.port, k.proto, k.vhost, r.id, r.started_at,
		       EXISTS (SELECT 1 FROM services s WHERE s.run_id = r.id AND s.ip = k.ip
		               AND s.port = k.port AND s.proto = k.proto AND s.vhost = k.vhost)
		FROM k CROSS JOIN r
		WHERE `+covers("k.ip")+`
		ORDER BY k.ip, k.port, k.proto, k.vhost, r.id`, lastRuns)
	if err != nil {
		return nil, err
	}
	return scanPresence(rows)
}

func scanPresence(rows pgx.Rows) ([]AssetPresence, error) {
	defer rows.Close()
	var out []AssetPresence
	for rows.Next() {
		var k model.AssetKey
		var ip string
		var port int
		var p Presence
		if err := rows.Scan(&ip, &port, &k.Proto, &k.VHost, &p.RunID, &p.StartedAt, &p.Seen); err != nil {
			return nil, err
		}
		var err error
		if k.IP, err = parseAddr(ip); err != nil {
			return nil, err
		}
		k.Port = uint16(port)
		if n := len(out); n == 0 || out[n-1].Key != k {
			out = append(out, AssetPresence{Key: k})
		}
		out[len(out)-1].Samples = append(out[len(out)-1].Samples, p)
	}
	return out, rows.Err()
}

// AssetHistory loads the newest lastRuns finished scan runs as seen from key
// (port 0 = host: seen means the host answered) and the key's changes.
func (s *Store) AssetHistory(ctx context.Context, key model.AssetKey, lastRuns int) (AssetTimeline, error) {
	h := AssetTimeline{Key: key}
	ip := key.IP.Unmap().String()
	rows, err := s.db.Query(ctx, `
		WITH r AS (`+lastScanRuns+`)
		SELECT r.id, r.started_at, `+covers("$2::inet")+`,
		       CASE WHEN $3::int = 0
		            THEN coalesce((SELECT up FROM host_obs h WHERE h.run_id = r.id AND h.ip = $2::inet), false)
		            ELSE s.id IS NOT NULL END,
		       coalesce(s.product, ''), coalesce(s.version, ''), coalesce(ho.status, 0), coalesce(ho.title, '')
		FROM r
		LEFT JOIN services s ON $3::int <> 0 AND s.run_id = r.id AND s.ip = $2::inet
		     AND s.port = $3::int AND s.proto = $4::text AND s.vhost = $5::text
		LEFT JOIN http_obs ho ON ho.service_id = s.id
		ORDER BY r.id`, lastRuns, ip, int(key.Port), key.Proto, key.VHost)
	if err != nil {
		return h, err
	}
	h.Runs, err = collect(rows, func(r pgx.Rows) (AssetRun, error) {
		var a AssetRun
		err := r.Scan(&a.RunID, &a.StartedAt, &a.Covered, &a.Seen, &a.Product, &a.Version,
			&a.HTTPStatus, &a.HTTPTitle)
		return a, err
	})
	if err != nil {
		return h, err
	}

	crows, err := s.db.Query(ctx, `
		SELECT run_id, coalesce(prev_run_id, 0), kind, field, old, new
		FROM changes WHERE ip = $1::inet AND port = $2 AND proto = $3 AND vhost = $4
		ORDER BY run_id DESC, id LIMIT $5`, ip, int(key.Port), key.Proto, key.VHost, maxHistoryChanges)
	if err != nil {
		return h, err
	}
	h.Changes, err = collect(crows, func(r pgx.Rows) (model.Change, error) {
		c := model.Change{Key: key}
		var kind string
		err := r.Scan(&c.RunID, &c.PrevRunID, &kind, &c.Field, &c.Old, &c.New)
		c.Kind = model.ChangeKind(kind)
		return c, err
	})
	return h, err
}
