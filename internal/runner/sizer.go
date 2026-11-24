package runner

import (
	"math/bits"
	"sync"
	"time"
)

// Group sizing defaults (addresses per nmap invocation).
const (
	DefaultInitialGroup = 256 // a /24 before any timing is known
	MinGroup            = 64
	MaxGroup            = 4096
	DefaultGroupTarget  = 90 * time.Second
	DefaultEWMAAlpha    = 0.3
)

// Sizer picks how many addresses a worker hands to one nmap invocation so
// that it takes roughly Target. It keeps an EWMA of seconds per address over
// finished groups and clamps the result to [Min, Max], rounded down to a
// power of two. Chunks are fixed when the run is created, so the size only
// decides how many leased chunks are scanned together. Safe for concurrent
// use by the workers of a run.
type Sizer struct {
	Initial int           // size before the first observation
	Target  time.Duration // desired duration of one group
	Min     int
	Max     int
	Alpha   float64 // EWMA weight of the newest observation, (0,1]

	mu      sync.Mutex
	ewma    float64 // seconds per address
	samples int
}

// NewSizer returns a sizer with the default clamp (64..4096). initial <= 0
// means DefaultInitialGroup, target <= 0 DefaultGroupTarget.
func NewSizer(initial int, target time.Duration) *Sizer {
	if initial <= 0 {
		initial = DefaultInitialGroup
	}
	if target <= 0 {
		target = DefaultGroupTarget
	}
	return &Sizer{Initial: initial, Target: target, Min: MinGroup, Max: MaxGroup, Alpha: DefaultEWMAAlpha}
}

// Observe feeds the measured duration of a scanned group of addrs addresses.
func (s *Sizer) Observe(addrs int, d time.Duration) {
	if addrs <= 0 || d < 0 {
		return
	}
	spa := d.Seconds() / float64(addrs)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.samples == 0 {
		s.ewma = spa
	} else {
		a := s.Alpha
		if a <= 0 || a > 1 {
			a = DefaultEWMAAlpha
		}
		s.ewma = a*spa + (1-a)*s.ewma
	}
	s.samples++
}

// Next returns the size (addresses) of the next group.
func (s *Sizer) Next() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	lo, hi := s.Min, s.Max
	if lo <= 0 {
		lo = MinGroup
	}
	hi = max(hi, lo)
	want := float64(s.Initial)
	if s.samples > 0 {
		want = float64(hi)
		if s.ewma > 0 {
			want = s.Target.Seconds() / s.ewma
		}
	}
	n := hi
	if want < float64(hi) {
		n = max(int(want), lo)
	}
	return floorPow2(n)
}

// floorPow2 returns the largest power of two <= n (n >= 1).
func floorPow2(n int) int {
	if n < 1 {
		return 1
	}
	return 1 << (bits.Len(uint(n)) - 1)
}
