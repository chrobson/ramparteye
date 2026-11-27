package main

import (
	"bytes"
	"context"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/ctx42/testing/pkg/assert"
)

func TestRunHooksCallsEveryHookInOrder(t *testing.T) {
	var logs bytes.Buffer
	var got []string
	rec := func(name string) func(context.Context, int64, string) {
		return func(_ context.Context, id int64, status string) {
			got = append(got, name+":"+status)
		}
	}
	boom := func(context.Context, int64, string) { panic("boom") }

	hook := runHooks(slog.New(slog.NewTextHandler(&logs, nil)), rec("dojo"), boom, rec("notify"))
	hook(context.Background(), 7, "done")

	assert.Equal(t, []string{"dojo:done", "notify:done"}, got)
	assert.Contain(t, "run hook panicked", logs.String())
}

func TestShutdownClosesNotifierAfterPusher(t *testing.T) {
	var mu sync.Mutex
	var steps []string
	rec := func(s string) {
		mu.Lock()
		defer mu.Unlock()
		steps = append(steps, s)
	}

	shutdown(slog.New(slog.DiscardHandler), time.Second, shutdownSteps{
		waitRuns:    func() { rec("wait runs") },
		closePusher: func(context.Context) error { rec("close pusher"); return nil },
		closeNotifier: func(ctx context.Context) error {
			rec("close notifier")
			assert.NoError(t, ctx.Err())
			return nil
		},
	})

	assert.Equal(t, []string{"wait runs", "close pusher", "close notifier"}, steps)
}

func TestShutdownWaitsForNotificationsBeforeClose(t *testing.T) {
	var mu sync.Mutex
	var steps []string
	rec := func(s string) {
		mu.Lock()
		defer mu.Unlock()
		steps = append(steps, s)
	}
	sent := make(chan struct{})
	go func() {
		time.Sleep(50 * time.Millisecond)
		rec("notification sent")
		close(sent)
	}()

	shutdown(slog.New(slog.DiscardHandler), time.Second, shutdownSteps{
		waitRuns:      func() { rec("wait runs") },
		waitPushes:    func() {},
		waitNotify:    func() { <-sent },
		pushBudget:    time.Second,
		closePusher:   func(context.Context) error { rec("close pusher"); return nil },
		closeNotifier: func(context.Context) error { rec("close notifier"); return nil },
	})

	assert.Equal(t, []string{"wait runs", "notification sent", "close pusher", "close notifier"}, steps)
}

func TestShutdownPushBudgetBoundsNotifyWait(t *testing.T) {
	var logs bytes.Buffer
	stuck := make(chan struct{})
	defer close(stuck)
	closed := false
	t0 := time.Now()

	shutdown(slog.New(slog.NewTextHandler(&logs, nil)), time.Second, shutdownSteps{
		waitNotify: func() { <-stuck },
		pushBudget: 50 * time.Millisecond,
		closeNotifier: func(context.Context) error {
			closed = true
			return nil
		},
	})

	assert.True(t, time.Since(t0) < 500*time.Millisecond)
	assert.True(t, closed)
	assert.Contain(t, "webhook notifications still running", logs.String())
}
