package auth

import (
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

func throttleKeys(login, ip string) []string {
	return []string{"login:" + strings.ToLower(login), "ip:" + ip}
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

// blocked reports whether any key is over the limit and for how long.
func (t *throttle) blocked(keys ...string) (bool, time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	var wait time.Duration
	for _, k := range keys {
		if fs := t.prune(k, now); len(fs) >= MaxLoginFailures {
			if w := LoginFailureWindow - now.Sub(fs[len(fs)-MaxLoginFailures]); w > wait {
				wait = w
			}
		}
	}
	return wait > 0, wait
}

func (t *throttle) fail(keys ...string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	for _, k := range keys {
		fs := t.prune(k, now)
		if len(fs) >= 4*MaxLoginFailures { // bound memory per key
			fs = fs[1:]
		}
		t.failures[k] = append(fs, now)
	}
	if len(t.failures) > 10000 { // bound memory overall
		for k := range t.failures {
			t.prune(k, now)
		}
	}
}

func (t *throttle) reset(key string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.failures, key)
}
