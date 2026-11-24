package runner

import (
	"context"
	"net/netip"
	"testing"

	"github.com/ctx42/testing/pkg/assert"

	"github.com/chrobson/ramparteye/internal/model"
	"github.com/chrobson/ramparteye/internal/safety"
)

// total sums the saved receipt deltas of a run.
func total(t *testing.T, fs *fakeStore, runID int64) safety.Receipt {
	t.Helper()
	rc, err := fs.SafetyReceipt(context.Background(), runID)
	assert.NoError(t, err)
	return rc
}

// Every nmap invocation (discovery and services) is metered, its targets
// re-checked against the scope, and the receipt saved per chunk group and at
// the end of the run.
func TestReceiptMetersEveryInvocation(t *testing.T) {
	f := setup(t, model.Target{Kind: model.TargetCIDR, Value: "10.20.0.0/22"})
	f.fs.configs[0].Workers = 1
	runID := f.runNow(t)

	calls := f.sc.discovers + f.sc.services
	rc := total(t, f.fs, runID)
	assert.Equal(t, calls, rc.NmapInvocations)
	assert.Equal(t, int64(10*calls), rc.NmapPackets)
	assert.Equal(t, int64(4*256+4), rc.TargetsChecked) // 4 chunks + 4 live hosts
	assert.Equal(t, int64(0), rc.TargetsOutsideAllowlist)
	assert.Equal(t, 1000, rc.ConfiguredMaxRate)
	assert.Equal(t, 1000, rc.PerWorkerRate)
	assert.Equal(t, 20.0, rc.HTTPRateLimit)
	// One save per nmap group plus the final one.
	assert.True(t, len(f.fs.savedReceipts()) >= len(f.sc.discoverGroups())+1)
	for _, r := range f.fs.savedReceipts() {
		assert.Equal(t, runID, r.RunID)
	}
}

// A failed nmap invocation is metered too (the scanner returns its Run with
// the error).
func TestReceiptMetersFailedInvocation(t *testing.T) {
	f := setup(t, model.Target{Kind: model.TargetCIDR, Value: "10.20.0.0/24"})
	f.sc.fail[pfx("10.20.0.0/24")] = true
	runID := f.runNow(t)
	assert.Equal(t, DefaultMaxAttempts, total(t, f.fs, runID).NmapInvocations)
}

// A failed save is restored into the meter and saved with the next delta:
// nothing is lost.
func TestReceiptRestoredAfterFailedSave(t *testing.T) {
	f := setup(t, model.Target{Kind: model.TargetCIDR, Value: "10.20.0.0/22"})
	f.fs.configs[0].Workers = 1
	f.fs.failSaves = 1
	runID := f.runNow(t)
	calls := f.sc.discovers + f.sc.services
	rc := total(t, f.fs, runID)
	assert.Equal(t, calls, rc.NmapInvocations)
	assert.Equal(t, int64(10*calls), rc.NmapPackets)
}

// Path probes go through the per-run gate: the signature count is reported
// before evaluating, web services are counted, and probes spent by earlier
// sessions of the run (resume) count against the per-host budget.
func TestReceiptPathProbes(t *testing.T) {
	f, ff := pipelineFixture(t, headerSig, pathSig)
	f.r.cfg.PathProbesPerHost = 1
	runID := f.runNow(t)
	rc := total(t, f.fs, runID)
	assert.True(t, rc.PathProbeSignaturesKnown)
	assert.Equal(t, 1, rc.PathProbeSignatures)
	assert.Equal(t, int64(1), rc.PathProbeWebServices)
	assert.Equal(t, int64(1), rc.PathProbes)
	assert.Equal(t, 1, rc.PathProbeBudget)
	assert.Equal(t, 1, ff.calls)

	// Resumed run whose host already spent its budget: the probe is refused.
	f, ff = pipelineFixture(t, headerSig, pathSig)
	f.r.cfg.PathProbesPerHost = 1
	f.fs.probes = map[netip.Addr]int{netip.MustParseAddr("10.20.0.10"): 1}
	runID = f.runNow(t)
	rc = total(t, f.fs, runID)
	assert.Equal(t, int64(0), rc.PathProbes)
	assert.Equal(t, int64(1), rc.PathProbesRefused)
	assert.Equal(t, 0, ff.calls)
	for _, ds := range f.fs.detections {
		for _, d := range ds {
			assert.NotEqual(t, "test-status", d.SignatureID)
		}
	}
}

// The shared engine is never modified: each run gets its own gate.
func TestReceiptSharedEngineUntouched(t *testing.T) {
	f, _ := pipelineFixture(t, headerSig, pathSig)
	f.runNow(t)
	assert.Nil(t, f.r.eng.ProbeGate)
}

// Recover syncs the built-in signatures into the store and loads the
// enabled ones into the engine.
func TestRecoverSyncsSignatures(t *testing.T) {
	f, _ := pipelineFixture(t, headerSig)
	assert.NoError(t, f.r.Recover(context.Background()))
	assert.Equal(t, 1, f.fs.synced)
	assert.NotEmpty(t, f.fs.sigRows)
	assert.True(t, len(f.r.eng.Signatures()) > 1)
}
