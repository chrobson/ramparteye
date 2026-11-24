package auth

import (
	"net/netip"
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
}

func newThrottle(now func() time.Time) *throttle {
	return &throttle{failures: map[string][]time.Time{}, now: now}
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

// reserve atomically checks the limit and, when not exceeded, counts one
// attempt against every key before the password is verified. Concurrent
// attempts therefore cannot all slip under the limit. On a successful login
// call release. When blocked it returns the remaining wait.
func (t *throttle) reserve(keys ...string) (ok bool, wait time.Duration) {
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
		return false, wait
	}
	for _, k := range keys {
		if _, known := t.failures[k]; !known && len(t.failures) >= maxThrottleKeys {
			t.makeRoom(now)
		}
		t.failures[k] = append(t.failures[k], now)
	}
	return true, 0
}

// makeRoom frees at least one slot: expired keys first, then the key whose
// newest failure is oldest. Caller holds mu.
func (t *throttle) makeRoom(now time.Time) {
	for k := range t.failures {
		t.prune(k, now)
	}
	if len(t.failures) < maxThrottleKeys {
		return
	}
	var oldest string
	var oldestAt time.Time
	for k, fs := range t.failures {
		if last := fs[len(fs)-1]; oldest == "" || last.Before(oldestAt) {
			oldest, oldestAt = k, last
		}
	}
	delete(t.failures, oldest)
}

// release undoes a reservation after a successful login: the login key is
// cleared and the client key loses the one attempt reserved at reservedAt.
func (t *throttle) release(loginKey, clientKey string, reservedAt time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.failures, loginKey)
	fs := t.failures[clientKey]
	for i, f := range fs {
		if f.Equal(reservedAt) {
			fs = append(fs[:i:i], fs[i+1:]...)
			break
		}
	}
	if len(fs) == 0 {
		delete(t.failures, clientKey)
	} else {
		t.failures[clientKey] = fs
	}
}
