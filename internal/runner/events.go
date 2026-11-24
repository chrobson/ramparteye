package runner

import "sync"

// Event kinds.
const (
	EventStarted  = "started"  // a run session started (new run or resume)
	EventProgress = "progress" // chunks or post-processing advanced
	EventFinished = "finished" // the session ended; Message holds the run status
)

// subscriberBuffer is how many events a subscriber may lag behind before the
// oldest are dropped.
const subscriberBuffer = 64

// Share of the progress bar taken by scanning; post-processing (HTTP
// fingerprinting, signatures, diff) fills the rest.
const scanShare = 0.9

// Event reports what a run is doing. Progress grows monotonically per run
// and is 1.0 only on the finished event of a final (done, failed or
// cancelled) run. PPS is the run's measured nmap packet rate so far.
type Event struct {
	RunID    int64
	Kind     string
	Progress float64
	PPS      int
	Message  string
}

type subscriber struct {
	ch   chan Event
	once sync.Once
}

type broker struct {
	mu       sync.Mutex
	subs     map[*subscriber]struct{}
	progress map[int64]float64 // highest progress published per active run
}

// Subscribe returns a channel of run events and a function that ends the
// subscription and closes the channel (safe to call more than once).
// Publishing never blocks: a subscriber that falls more than
// subscriberBuffer events behind loses its oldest events, so it always ends
// up with the newest ones.
func (r *Runner) Subscribe() (<-chan Event, func()) {
	s := &subscriber{ch: make(chan Event, subscriberBuffer)}
	b := &r.events
	b.mu.Lock()
	if b.subs == nil {
		b.subs = map[*subscriber]struct{}{}
	}
	b.subs[s] = struct{}{}
	b.mu.Unlock()
	return s.ch, func() {
		s.once.Do(func() {
			b.mu.Lock()
			delete(b.subs, s)
			close(s.ch)
			b.mu.Unlock()
		})
	}
}

// publish fans e out to every subscriber without blocking. Progress is
// clamped to [0, 1] and never goes below what was already published for the
// run; the finished event forgets the run.
func (r *Runner) publish(e Event) {
	b := &r.events
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.progress == nil {
		b.progress = map[int64]float64{}
	}
	e.Progress = max(min(e.Progress, 1), 0, b.progress[e.RunID])
	if e.Kind == EventFinished {
		delete(b.progress, e.RunID)
	} else {
		b.progress[e.RunID] = e.Progress
	}
	for s := range b.subs {
		select {
		case s.ch <- e:
			continue
		default:
		}
		select { // full: drop the oldest event, then retry once
		case <-s.ch:
		default:
		}
		select {
		case s.ch <- e:
		default:
		}
	}
}
