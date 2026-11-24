package auth

import (
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"
)

// Login throttling: after MaxLoginFailures failed attempts within
// LoginFailureWindow for one login or from one client address, further
// attempts are refused until the oldest failure leaves the window.
const (
	MaxLoginFailures   = 5
	LoginFailureWindow = 15 * time.Minute
)

type throttle struct {
	mu       sync.Mutex
	failures map[string][]time.Time
	now      func() time.Time

	lastSweep time.Time
	maxKeys   int
}

func newThrottle(now func() time.Time) *throttle {
	return &throttle{failures: map[string][]time.Time{}, now: now, maxKeys: maxThrottleKeys}
}

// MaxLoginLen is the longest login that is keyed; longer ones are rejected.
const MaxLoginLen = 256

// maxThrottleKeys is the hard cap on tracked keys.
const maxThrottleKeys = 10000

func throttleKeys(login, ip string) []string {
	return []string{"login:" + strings.ToLower(login), "ip:" + clientKey(ip)}
}

// clientKey normalises a client address: IPv4-mapped IPv6 becomes IPv4 and
// IPv6 clients are keyed per /64, so one host cannot rotate through its
// prefix to dodge the limit.
func clientKey(ip string) string {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return "invalid"
	}
	a = a.Unmap().WithZone("")
	if a.Is6() {
		p, _ := a.Prefix(64)
		return p.String()
	}
	return a.String()
}

// prune drops failures older than the window; caller holds mu.
func (t *throttle) prune(key string, now time.Time) []time.Time {
	fs := t.failures[key]
	i := 0
	for i < len(fs) && now.Sub(fs[i]) >= LoginFailureWindow {
		i++
	}
	fs = fs[i:]
	if len(fs) == 0 {
		delete(t.failures, key)
	} else {
		t.failures[key] = fs
	}
	return fs
}

// reservation is one counted attempt; release removes exactly it.
type reservation struct {
	keys []string
	at   time.Time
}

// reserve atomically checks the limit and, when not exceeded, counts one
// attempt against every key before the password is verified. Concurrent
// attempts therefore cannot all slip under the limit. When blocked it
// returns the remaining wait. If the key table is full of blocked keys the
// request is refused as well (fail closed) rather than evicting a lock.
func (t *throttle) reserve(keys ...string) (res reservation, ok bool, wait time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	for _, k := range keys {
		if fs := t.prune(k, now); len(fs) >= MaxLoginFailures {
			if w := LoginFailureWindow - now.Sub(fs[len(fs)-MaxLoginFailures]); w > wait {
				wait = w
			}
		}
	}
	if wait > 0 {
		return reservation{}, false, wait
	}
	for _, k := range keys {
		if _, known := t.failures[k]; !known {
			if !t.makeRoom(now, keys) {
				return reservation{}, false, LoginFailureWindow
			}
		}
		t.failures[k] = append(t.failures[k], now)
	}
	return reservation{keys: keys, at: now}, true, 0
}

// makeRoom ensures a free slot when the table is full: expired keys go
// first, then the non-blocked key with the fewest failures (oldest on
// ties). Blocked keys and the request's own keys are never evicted; it
// reports false when no slot can be freed. Caller holds mu.
func (t *throttle) makeRoom(now time.Time, own []string) bool {
	if len(t.failures) < t.maxKeys {
		return true
	}
	if now.Sub(t.lastSweep) >= time.Minute { // full sweeps are O(n); rate-limit them
		t.lastSweep = now
		for k := range t.failures {
			t.prune(k, now)
		}
		if len(t.failures) < t.maxKeys {
			return true
		}
	}
	var victim string
	var victimFS []time.Time
	for k, fs := range t.failures {
		if len(fs) >= MaxLoginFailures || slices.Contains(own, k) {
			continue
		}
		if victim == "" || len(fs) < len(victimFS) ||
			(len(fs) == len(victimFS) && fs[len(fs)-1].Before(victimFS[len(victimFS)-1])) {
			victim, victimFS = k, fs
		}
	}
	if victim == "" {
		return false
	}
	delete(t.failures, victim)
	return true
}

// release removes the attempt counted by res from every key. When success
// is true (correct password) the login key is cleared as well; error paths
// leave earlier real failures alone.
func (t *throttle) release(res reservation, success bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, k := range res.keys {
		fs := t.failures[k]
		for i, f := range fs {
			if f.Equal(res.at) {
				fs = append(fs[:i:i], fs[i+1:]...)
				break
			}
		}
		if len(fs) == 0 {
			delete(t.failures, k)
		} else {
			t.failures[k] = fs
		}
	}
	if success && len(res.keys) > 0 {
		delete(t.failures, res.keys[0])
	}
}
