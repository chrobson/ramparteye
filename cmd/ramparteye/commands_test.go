package main

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/ctx42/testing/pkg/assert"
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
