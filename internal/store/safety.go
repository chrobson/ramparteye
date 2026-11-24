package store

import (
	"context"
	"net/netip"

	"github.com/chrobson/ramparteye/internal/safety"
)

// SaveSafetyReceipt adds a receipt delta (from safety.Meter.Drain) to the
// run's stored safety receipt.
func (s *Store) SaveSafetyReceipt(ctx context.Context, r safety.Receipt) error {
	return safety.Save(ctx, s.db, r)
}

// SafetyReceipt loads the stored safety receipt of a run
// (safety.ErrNoReceipt when there is none).
func (s *Store) SafetyReceipt(ctx context.Context, runID int64) (safety.Receipt, error) {
	return safety.Load(ctx, s.db, runID)
}

// SafetyProbes returns the path probes a run already sent per host.
func (s *Store) SafetyProbes(ctx context.Context, runID int64) (map[netip.Addr]int, error) {
	return safety.LoadProbes(ctx, s.db, runID)
}
