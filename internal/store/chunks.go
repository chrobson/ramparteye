package store

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/chrobson/ramparteye/internal/model"
)

// Chunk statuses (scan_chunks.status).
const (
	ChunkPending = "pending"
	ChunkRunning = "running"
	ChunkDone    = "done"
	ChunkFailed  = "failed"
)

// Chunk is a leased unit of work.
type Chunk struct {
	ID       int64
	RunID    int64
	Prefix   netip.Prefix
	Attempts int // including the current lease
}

// ChunkCounts counts the chunks of a run per status.
type ChunkCounts struct {
	Pending, Running, Done, Failed int
}

// LeaseChunk takes the next pending chunk of a run. Concurrent workers, in
// this or another process, never get the same chunk (SKIP LOCKED).
func (s *Store) LeaseChunk(ctx context.Context, runID int64) (Chunk, bool, error) {
	c := Chunk{RunID: runID}
	err := s.db.QueryRow(ctx, `
		UPDATE scan_chunks SET status = 'running', attempts = attempts + 1, started_at = now()
		WHERE id = (
			SELECT id FROM scan_chunks
			WHERE run_id = $1 AND status = 'pending'
			ORDER BY id
			FOR UPDATE SKIP LOCKED
			LIMIT 1)
		RETURNING id, cidr, attempts`, runID).Scan(&c.ID, &c.Prefix, &c.Attempts)
	if errors.Is(err, pgx.ErrNoRows) {
		return c, false, nil
	}
	if err != nil {
		return c, false, err
	}
	return c, true, nil
}

// ErrLeaseLost is returned when a chunk is no longer leased by the caller:
// it was reset and leased again (its attempts moved on), or it is not
// running any more. The caller must drop its result.
var ErrLeaseLost = errors.New("chunk lease lost")

// leaseGuard matches the row of chunk c only while c's lease is current:
// attempts acts as the lease token, so a stale worker cannot complete or
// requeue a chunk that was re-leased to another worker.
const leaseGuard = ` WHERE id = $1 AND status = 'running' AND attempts = $2`

func leaseResult(tag pgconn.CommandTag, err error) error {
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrLeaseLost
	}
	return nil
}

// CompleteChunk stores the observations of a chunk and marks it done in one
// transaction; the number of hosts up is recorded on the chunk. Nothing is
// stored and ErrLeaseLost is returned when c's lease is no longer current.
func (s *Store) CompleteChunk(ctx context.Context, c Chunk, dur time.Duration, hosts []model.HostObs, svcs []model.ServiceObs) error {
	up := 0
	for _, h := range hosts {
		if h.Up {
			up++
		}
	}
	return s.InTx(ctx, func(tx *Store) error {
		err := leaseResult(tx.db.Exec(ctx, `UPDATE scan_chunks SET status = 'done', duration_ms = $3, hosts_up = $4,
			last_error = ''`+leaseGuard, c.ID, c.Attempts, dur.Milliseconds(), up))
		if err != nil {
			return err
		}
		return tx.InsertObservations(ctx, c.RunID, hosts, svcs)
	})
}

// ReleaseChunk returns a chunk to pending after a retryable error.
func (s *Store) ReleaseChunk(ctx context.Context, c Chunk, reason string) error {
	return leaseResult(s.db.Exec(ctx, `UPDATE scan_chunks SET status = 'pending', last_error = $3`+leaseGuard,
		c.ID, c.Attempts, reason))
}

// InterruptChunk returns a chunk to pending after an interruption (window
// end, stop, shutdown) and refunds the attempt its lease took.
func (s *Store) InterruptChunk(ctx context.Context, c Chunk, reason string) error {
	return leaseResult(s.db.Exec(ctx, `UPDATE scan_chunks SET status = 'pending', last_error = $3,
		attempts = greatest(attempts - 1, 0)`+leaseGuard, c.ID, c.Attempts, reason))
}

// FailChunk marks a chunk permanently failed.
func (s *Store) FailChunk(ctx context.Context, c Chunk, reason string) error {
	return leaseResult(s.db.Exec(ctx, `UPDATE scan_chunks SET status = 'failed', last_error = $3`+leaseGuard,
		c.ID, c.Attempts, reason))
}

// CountChunks counts the chunks of a run per status.
func (s *Store) CountChunks(ctx context.Context, runID int64) (ChunkCounts, error) {
	var c ChunkCounts
	err := s.db.QueryRow(ctx, `SELECT
		count(*) FILTER (WHERE status = 'pending'),
		count(*) FILTER (WHERE status = 'running'),
		count(*) FILTER (WHERE status = 'done'),
		count(*) FILTER (WHERE status = 'failed')
		FROM scan_chunks WHERE run_id = $1`, runID).Scan(&c.Pending, &c.Running, &c.Done, &c.Failed)
	return c, err
}
