//go:build integration

package store_test

import (
	"net/netip"
	"testing"

	"github.com/ctx42/testing/pkg/assert"
	"github.com/ctx42/testing/pkg/must"

	"github.com/chrobson/ramparteye/internal/safety"
)

func TestSafetyReceiptRoundTrip(t *testing.T) {
	s, pool := newStore(t)
	runID := insertRun(t, pool, "scan", "done")

	_, err := s.SafetyReceipt(ctx, runID)
	assert.ErrorIs(t, safety.ErrNoReceipt, err)
	assert.Len(t, 0, must.Value(s.SafetyProbes(ctx, runID)))

	r := safety.Receipt{RunID: runID, NmapInvocations: 2, NmapPackets: 300, PathProbes: 3,
		ProbeHosts: map[string]int{"10.20.0.10": 3}}
	assert.NoError(t, s.SaveSafetyReceipt(ctx, r))
	assert.NoError(t, s.SaveSafetyReceipt(ctx, safety.Receipt{RunID: runID, NmapPackets: 100}))

	got := must.Value(s.SafetyReceipt(ctx, runID))
	assert.Equal(t, int64(400), got.NmapPackets)
	assert.Equal(t, 2, got.NmapInvocations)
	assert.Equal(t, map[netip.Addr]int{addr("10.20.0.10"): 3}, must.Value(s.SafetyProbes(ctx, runID)))
}
