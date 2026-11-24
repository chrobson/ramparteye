package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/chrobson/ramparteye/internal/model"
)

const hostStateCols = `host(ip), state, misses, flips, first_seen, last_seen`

func scanHostState(r pgx.Rows) (model.HostState, error) {
	var h model.HostState
	var ip, state string
	var flips []byte
	if err := r.Scan(&ip, &state, &h.Misses, &flips, &h.FirstSeen, &h.LastSeen); err != nil {
		return h, err
	}
	var err error
	if h.IP, err = parseAddr(ip); err != nil {
		return h, err
	}
	h.State = model.HostStateKind(state)
	if err := json.Unmarshal(flips, &h.Flips); err != nil {
		return h, fmt.Errorf("host_state %s flips: %w", ip, err)
	}
	return h, nil
}

// HostStatesInScope returns, and inside InTx locks, the states of known
// hosts covered by runID: hosts inside a scan's chunk prefixes, only the
// hosts of an import, or every host for a scan without chunks.
func (s *Store) HostStatesInScope(ctx context.Context, runID int64) ([]model.HostState, error) {
	rows, err := s.db.Query(ctx, `SELECT `+hostStateCols+` FROM host_state hs
		WHERE `+inScope("hs.ip", "$1")+` ORDER BY hs.ip FOR UPDATE OF hs`, runID)
	if err != nil {
		return nil, err
	}
	return collect(rows, scanHostState)
}

// HostStates returns every known host, or only those in state when it is
// not empty.
func (s *Store) HostStates(ctx context.Context, state model.HostStateKind) ([]model.HostState, error) {
	rows, err := s.db.Query(ctx, `SELECT `+hostStateCols+` FROM host_state
		WHERE $1 = '' OR state = $1 ORDER BY ip`, string(state))
	if err != nil {
		return nil, err
	}
	return collect(rows, scanHostState)
}

// HostStateCounts returns the number of hosts per state.
func (s *Store) HostStateCounts(ctx context.Context) (map[model.HostStateKind]int, error) {
	rows, err := s.db.Query(ctx, `SELECT state, count(*) FROM host_state GROUP BY state`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[model.HostStateKind]int{}
	for rows.Next() {
		var st string
		var n int
		if err := rows.Scan(&st, &n); err != nil {
			return nil, err
		}
		out[model.HostStateKind(st)] = n
	}
	return out, rows.Err()
}

// SaveHostStates upserts host states. first_seen is kept for known hosts; a
// zero FirstSeen means now and a zero LastSeen means FirstSeen.
func (s *Store) SaveHostStates(ctx context.Context, hs []model.HostState) error {
	b := &pgx.Batch{}
	for _, h := range hs {
		flips, err := json.Marshal(nonNilSlice(h.Flips))
		if err != nil {
			return err
		}
		first, last := h.FirstSeen, h.LastSeen
		if first.IsZero() {
			first = time.Now()
		}
		if last.IsZero() {
			last = first
		}
		b.Queue(`INSERT INTO host_state (ip, state, misses, flips, first_seen, last_seen)
			VALUES ($1::inet, $2, $3, $4::jsonb, $5, $6)
			ON CONFLICT (ip) DO UPDATE SET state = EXCLUDED.state, misses = EXCLUDED.misses,
				flips = EXCLUDED.flips, last_seen = EXCLUDED.last_seen`,
			h.IP.Unmap().String(), string(h.State), h.Misses, string(flips), first, last)
	}
	if b.Len() == 0 {
		return nil
	}
	return s.db.SendBatch(ctx, b).Close()
}
