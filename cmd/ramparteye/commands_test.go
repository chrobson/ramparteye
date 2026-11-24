package main

import (
	"bytes"
	"context"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/ctx42/testing/pkg/assert"

	"github.com/chrobson/ramparteye/internal/config"
	"github.com/chrobson/ramparteye/internal/diff"
	"github.com/chrobson/ramparteye/internal/safety"
)

func TestArgumentErrorsExit2(t *testing.T) {
	for name, tc := range map[string]struct {
		args []string
		want string
	}{
		"migrate extra":      {[]string{"migrate", "x"}, "usage: ramparteye migrate"},
		"serve extra":        {[]string{"serve", "x"}, "usage: ramparteye serve"},
		"audit two":          {[]string{"audit", "1", "2"}, "usage: ramparteye audit [run]"},
		"audit bad":          {[]string{"audit", "x"}, `invalid run id "x"`},
		"dojo nothing":       {[]string{"dojo"}, "usage: ramparteye dojo push [--run ID]"},
		"dojo other":         {[]string{"dojo", "pull"}, "usage: ramparteye dojo push [--run ID]"},
		"dojo bad run":       {[]string{"dojo", "push", "--run", "-3"}, `invalid run id "-3"`},
		"dojo extra":         {[]string{"dojo", "push", "7"}, "usage: ramparteye dojo push [--run ID]"},
		"reset-admin extra":  {[]string{"reset-admin", "x"}, "usage: ramparteye reset-admin [--login NAME]"},
		"reset-admin empty":  {[]string{"reset-admin", "--login", ""}, "usage: ramparteye reset-admin [--login NAME]"},
		"export bad run neg": {[]string{"export", "--run", "-1"}, `invalid run id "-1"`},
	} {
		t.Run(name, func(t *testing.T) {
			e, out, errb := testEnv(nil)

			code := e.run(append([]string{"ramparteye"}, tc.args...))

			assert.Equal(t, 2, code)
			assert.Equal(t, "", out.String())
			assert.Contain(t, tc.want, errb.String())
		})
	}
}

func TestParseRunID(t *testing.T) {
	id, err := parseRunID("12")
	assert.NoError(t, err)
	assert.Equal(t, int64(12), id)

	for _, bad := range []string{"0", "-1", "x", ""} {
		_, err := parseRunID(bad)
		assert.ErrorContain(t, "invalid run id", err)
	}
}

type fakeTicker struct {
	mu    sync.Mutex
	ticks []time.Time
}

func (f *fakeTicker) Tick(_ context.Context, now time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ticks = append(f.ticks, now)
}

func (f *fakeTicker) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.ticks)
}

func TestTickLoopTicksImmediatelyAndPeriodically(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	f := &fakeTicker{}
	done := make(chan struct{})

	go func() {
		defer close(done)
		tickLoop(ctx, f, 5*time.Millisecond, time.Now)
	}()

	assert.Wait(t, time.Second, func() bool { return f.count() >= 3 })
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("tickLoop did not stop")
	}
}

func TestHTTPServerTimeouts(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	srv := newHTTPServer(nil, ctx, nil)

	assert.Equal(t, 10*time.Second, srv.ReadHeaderTimeout)
	assert.Equal(t, 2*time.Minute, srv.IdleTimeout)
	assert.Equal(t, time.Duration(0), srv.WriteTimeout) // SSE must stream
	assert.True(t, srv.BaseContext(nil) == ctx)
}

func TestShutdownOrder(t *testing.T) {
	var mu sync.Mutex
	var steps []string
	rec := func(s string) {
		mu.Lock()
		defer mu.Unlock()
		steps = append(steps, s)
	}
	loopDone := make(chan struct{})

	shutdown(slog.New(slog.DiscardHandler), time.Second, shutdownSteps{
		stopRuns: func() { rec("stop runs"); close(loopDone) },
		stopHTTP: func(context.Context) error { rec("stop http"); return nil },
		loopDone: loopDone,
		waitRuns: func() { rec("wait runs") },
		closePusher: func(ctx context.Context) error {
			rec("close pusher")
			assert.NoError(t, ctx.Err())
			return nil
		},
	})

	assert.Equal(t, []string{"stop runs", "stop http", "wait runs", "close pusher"}, steps)
}

func TestShutdownBudgetBoundsRunnerWait(t *testing.T) {
	var logs bytes.Buffer
	stuck := make(chan struct{})
	defer close(stuck)
	closed := false
	t0 := time.Now()

	shutdown(slog.New(slog.NewTextHandler(&logs, nil)), 50*time.Millisecond, shutdownSteps{
		waitRuns: func() { <-stuck },
		closePusher: func(ctx context.Context) error {
			closed = true
			assert.Error(t, ctx.Err()) // in-flight pushes are cancelled at once
			return ctx.Err()
		},
	})

	assert.True(t, time.Since(t0) < time.Second)
	assert.True(t, closed)
	assert.Contain(t, "scans still stopping at exit", logs.String())
}

func TestShutdownWaitsForPushesBeforeClose(t *testing.T) {
	var mu sync.Mutex
	var steps []string
	rec := func(s string) {
		mu.Lock()
		defer mu.Unlock()
		steps = append(steps, s)
	}
	pushed := make(chan struct{})
	go func() {
		time.Sleep(50 * time.Millisecond)
		rec("push done")
		close(pushed)
	}()

	shutdown(slog.New(slog.DiscardHandler), time.Second, shutdownSteps{
		waitRuns:   func() { rec("wait runs") },
		waitPushes: func() { <-pushed },
		pushBudget: time.Second,
		closePusher: func(ctx context.Context) error {
			rec("close pusher")
			return nil
		},
	})

	assert.Equal(t, []string{"wait runs", "push done", "close pusher"}, steps)
}

func TestShutdownPushBudgetBoundsPushWait(t *testing.T) {
	var logs bytes.Buffer
	stuck := make(chan struct{})
	defer close(stuck)
	closed := false
	t0 := time.Now()

	shutdown(slog.New(slog.NewTextHandler(&logs, nil)), time.Second, shutdownSteps{
		waitPushes: func() { <-stuck },
		pushBudget: 50 * time.Millisecond,
		closePusher: func(ctx context.Context) error {
			closed = true
			return nil
		},
	})

	assert.True(t, time.Since(t0) < 500*time.Millisecond)
	assert.True(t, closed)
	assert.Contain(t, "DefectDojo pushes still running", logs.String())
}

func TestLoadBoxWithoutCreate(t *testing.T) {
	dir := t.TempDir()
	_, _, err := loadBox(&config.Config{SecretsDir: dir}, false)
	assert.ErrorContain(t, "secret key not found in "+dir, err)

	cfg := config.Config{SecretsDir: dir}
	_, created, err := loadBox(&cfg, true)
	assert.NoError(t, err)
	assert.True(t, created)

	again := config.Config{SecretsDir: dir}
	_, created, err = loadBox(&again, false)
	assert.NoError(t, err)
	assert.False(t, created)
	assert.Equal(t, cfg.SecretKey, again.SecretKey)

	override := config.Config{SecretsDir: t.TempDir(), SecretKey: bytes.Repeat([]byte{7}, 32)}
	_, _, err = loadBox(&override, false)
	assert.NoError(t, err)
}

func TestRunnerConfigPathProbes(t *testing.T) {
	cfg := config.Config{PathProbesPerHost: 50, MaxRate: 900, ScanPorts: []int{22}, AllPortsMaxAddrs: 16,
		ScanPrivileged: true, HTTPTimeout: 3 * time.Second,
		Unstable: config.UnstableConfig{InactiveAfterMisses: 3, UnstableIfFlips: 2, Window: 5}}

	rc := runnerConfig(cfg, nil)

	assert.Equal(t, 50, rc.PathProbesPerHost)
	assert.Equal(t, 900, rc.MaxRate)
	assert.Equal(t, []int{22}, rc.AllowedPorts)
	assert.Equal(t, 16, rc.AllPortsMaxAddrs)
	assert.True(t, rc.Privileged)
	assert.Equal(t, 3*time.Second, rc.HTTPTimeout)
	assert.Equal(t, diff.Config{InactiveAfterMisses: 3, UnstableIfFlips: 2, Window: 5}, rc.Unstable)

	cfg.PathProbesPerHost = 0 // disabled, not unlimited
	assert.Equal(t, safety.PathProbesDisabled, runnerConfig(cfg, nil).PathProbesPerHost)
}
