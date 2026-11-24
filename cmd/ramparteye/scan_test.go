package main

import (
	"bytes"
	"testing"

	"github.com/ctx42/testing/pkg/assert"

	"github.com/chrobson/ramparteye/internal/model"
	"github.com/chrobson/ramparteye/internal/runner"
	"github.com/chrobson/ramparteye/internal/store"
)

func TestScanWithoutScopeExits2(t *testing.T) {
	for name, args := range map[string][]string{
		"profile": {"--profile", "Weekly"},
		"targets": {"10.0.0.1"},
	} {
		t.Run(name, func(t *testing.T) {
			e, out, errb := testEnv(nil)

			code := e.run(append([]string{"ramparteye", "scan"}, args...))

			assert.Equal(t, 2, code)
			assert.Equal(t, "", out.String())
			assert.Contain(t, "no scan scope configured: set RAMPART_ALLOWED_CIDRS", errb.String())
		})
	}
}

func TestScanUsageErrors(t *testing.T) {
	scope := map[string]string{"RAMPART_ALLOWED_CIDRS": "10.0.0.0/24"}
	for name, tc := range map[string]struct {
		args []string
		want string
	}{
		"nothing":       {nil, "usage: ramparteye scan"},
		"both":          {[]string{"--profile", "Weekly", "10.0.0.1"}, "either --profile or targets"},
		"empty profile": {[]string{"--profile", ""}, "usage: ramparteye scan"},
		"bad flag":      {[]string{"--nope"}, "flag provided but not defined: -nope"},
	} {
		t.Run(name, func(t *testing.T) {
			e, _, errb := testEnv(scope)

			code := e.run(append([]string{"ramparteye", "scan"}, tc.args...))

			assert.Equal(t, 2, code)
			assert.Contain(t, tc.want, errb.String())
		})
	}
}

func TestParseScanArgs(t *testing.T) {
	a, err := parseScanArgs([]string{"--profile", "Weekly"})
	assert.NoError(t, err)
	assert.Equal(t, scanArgs{profile: "Weekly"}, a)

	a, err = parseScanArgs([]string{"10.0.0.1", "10.0.0.0/30"})
	assert.NoError(t, err)
	assert.Equal(t, scanArgs{targets: []string{"10.0.0.1", "10.0.0.0/30"}}, a)
}

func TestFollowRunPrintsProgressUntilFinished(t *testing.T) {
	events := make(chan runner.Event, 10)
	events <- runner.Event{RunID: 3, Kind: runner.EventStarted}
	events <- runner.Event{RunID: 9, Kind: runner.EventProgress, Progress: 0.9} // another run
	events <- runner.Event{RunID: 3, Kind: runner.EventProgress, Progress: 0.25, PPS: 800}
	events <- runner.Event{RunID: 3, Kind: runner.EventProgress, Progress: 0.251, PPS: 810} // same percent
	events <- runner.Event{RunID: 3, Kind: runner.EventProgress, Progress: 0.5, PPS: 900, Message: "fingerprinting"}
	events <- runner.Event{RunID: 3, Kind: runner.EventFinished, Progress: 1, Message: "done"}
	var w bytes.Buffer

	status := followRun(events, make(chan struct{}), 3, &w)

	assert.Equal(t, "done", status)
	assert.Equal(t, "run 3 started\n"+
		"run 3: 25% (800 pps)\n"+
		"run 3: 50% (900 pps) fingerprinting\n"+
		"run 3 finished: done\n", w.String())
}

func TestFollowRunStopsWhenRunnerIdle(t *testing.T) {
	idle := make(chan struct{})
	close(idle)
	var w bytes.Buffer

	status := followRun(make(chan runner.Event), idle, 3, &w)

	assert.Equal(t, "", status)
}

func TestPrintScanSummary(t *testing.T) {
	ms := int64(62_000)
	run := store.RunSummary{ID: 7, Status: "done", DurationMS: &ms, HostsUp: 3, Services: 12, ChunksTotal: 4, ChunksFailed: 1}
	cr := store.ChangeRun{RunID: 7, PrevRunID: 6, Total: 3,
		Counts: map[model.ChangeKind]int{model.ChangeNew: 2, model.ChangeGone: 1}}
	var w bytes.Buffer

	printScanSummary(&w, run, cr)

	assert.Equal(t, "run 7 done in 1m2s: 3 hosts up, 12 services, 1 of 4 chunks failed\n"+
		"changes since run 6: 2 new, 1 gone\n", w.String())
}

func TestPrintScanSummaryBaselineAndNoChanges(t *testing.T) {
	run := store.RunSummary{ID: 1, Status: "done", HostsUp: 1, Services: 2, ChunksTotal: 1}
	var w bytes.Buffer

	printScanSummary(&w, run, store.ChangeRun{RunID: 1})
	printScanSummary(&w, store.RunSummary{ID: 2, Status: "done"}, store.ChangeRun{RunID: 2, PrevRunID: 1})

	assert.Equal(t, "run 1 done: 1 hosts up, 2 services\n"+
		"first run: stored as the baseline for change detection\n"+
		"run 2 done: 0 hosts up, 0 services\n"+
		"no changes since run 1\n", w.String())
}

func TestScanExitCode(t *testing.T) {
	assert.Equal(t, 0, scanExitCode("done"))
	assert.Equal(t, 1, scanExitCode("failed"))
	assert.Equal(t, 1, scanExitCode("cancelled"))
	assert.Equal(t, 1, scanExitCode("paused"))
}
