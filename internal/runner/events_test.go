package runner

import (
	"context"
	"testing"
	"time"

	"github.com/ctx42/testing/pkg/assert"

	"github.com/chrobson/ramparteye/internal/model"
	"github.com/chrobson/ramparteye/internal/store"
)

// collect reads events of runID until its finished event.
func collect(t *testing.T, ch <-chan Event, runID int64) []Event {
	t.Helper()
	var out []Event
	timeout := time.After(5 * time.Second)
	for {
		select {
		case e, ok := <-ch:
			if !ok {
				return out
			}
			if e.RunID != runID {
				continue
			}
			out = append(out, e)
			if e.Kind == EventFinished {
				return out
			}
		case <-timeout:
			t.Fatalf("no finished event; got %+v", out)
		}
	}
}

func TestEventsPublished(t *testing.T) {
	f := setup(t,
		model.Target{Kind: model.TargetCIDR, Value: "10.20.0.0/21"},
		model.Target{Kind: model.TargetIP, Value: "10.20.9.9"},
	)
	f.fs.configs[0].Workers = 2
	ch, unsubscribe := f.r.Subscribe()
	defer unsubscribe()

	runID, err := f.r.Start(context.Background(), f.cfg.ID)
	assert.NoError(t, err)
	events := collect(t, ch, runID)
	f.r.Wait()

	assert.True(t, len(events) >= 3)
	assert.Equal(t, EventStarted, events[0].Kind)
	last := events[len(events)-1]
	assert.Equal(t, EventFinished, last.Kind)
	assert.Equal(t, 1.0, last.Progress)
	assert.Contain(t, store.RunDone, last.Message)
	sawProgress, sawPPS := false, false
	for i, e := range events {
		if i > 0 {
			assert.True(t, e.Progress >= events[i-1].Progress)
		}
		assert.True(t, e.Progress >= 0 && e.Progress <= 1)
		sawProgress = sawProgress || (e.Kind == EventProgress && e.Progress > 0 && e.Progress < 1)
		sawPPS = sawPPS || e.PPS > 0
	}
	assert.True(t, sawProgress)
	assert.True(t, sawPPS)
}

// A paused run reports where it stopped, not 1.0.
func TestEventsPausedRun(t *testing.T) {
	f := setup(t, model.Target{Kind: model.TargetCIDR, Value: "10.20.0.0/23"})
	f.fs.configs[0].Workers = 1
	f.sc.setBlock(pfx("10.20.1.0/24"), true)
	ch, unsubscribe := f.r.Subscribe()
	defer unsubscribe()

	runID, err := f.r.Start(context.Background(), f.cfg.ID)
	assert.NoError(t, err)
	time.AfterFunc(50*time.Millisecond, func() { f.r.Stop(runID) })
	events := collect(t, ch, runID)
	f.r.Wait()
	last := events[len(events)-1]
	assert.Contain(t, store.RunPaused, last.Message)
	assert.True(t, last.Progress < 1)
}

// A subscriber that never reads must not block the runner; it keeps the
// newest events, ending with the finished one.
func TestSlowSubscriberDoesNotBlock(t *testing.T) {
	f := setup(t, model.Target{Kind: model.TargetCIDR, Value: "10.20.0.0/18"}) // 64 chunks
	f.fs.configs[0].Workers = 1
	ch, unsubscribe := f.r.Subscribe()
	defer unsubscribe()

	done := make(chan int64)
	go func() {
		id, _ := f.r.Start(context.Background(), f.cfg.ID)
		f.r.Wait()
		done <- id
	}()
	var runID int64
	select {
	case runID = <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("runner blocked by a slow subscriber")
	}
	assert.Equal(t, store.RunDone, f.fs.runStatus(runID))
	var last Event
	n := 0
	for len(ch) > 0 {
		last = <-ch
		n++
	}
	assert.True(t, n <= subscriberBuffer)
	assert.Equal(t, EventFinished, last.Kind)
}

func TestUnsubscribeClosesChannel(t *testing.T) {
	f := setup(t)
	ch, unsubscribe := f.r.Subscribe()
	unsubscribe()
	unsubscribe() // idempotent
	_, ok := <-ch
	assert.False(t, ok)
	f.r.publish(Event{RunID: 1, Kind: EventProgress}) // no panic on a closed subscriber
}

// Progress never goes back, even when a producer reports less (concurrent
// workers publish counts read at different times).
func TestPublishProgressMonotonic(t *testing.T) {
	f := setup(t)
	ch, unsubscribe := f.r.Subscribe()
	defer unsubscribe()
	f.r.publish(Event{RunID: 7, Kind: EventProgress, Progress: 0.5})
	f.r.publish(Event{RunID: 7, Kind: EventProgress, Progress: 0.3})
	f.r.publish(Event{RunID: 7, Kind: EventProgress, Progress: 1.7})
	f.r.publish(Event{RunID: 8, Kind: EventProgress, Progress: -1})
	assert.Equal(t, 0.5, (<-ch).Progress)
	assert.Equal(t, 0.5, (<-ch).Progress)
	assert.Equal(t, 1.0, (<-ch).Progress)
	assert.Equal(t, 0.0, (<-ch).Progress)
}
