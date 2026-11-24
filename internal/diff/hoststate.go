package diff

import (
	"net/netip"
	"slices"
	"time"

	"github.com/chrobson/ramparteye/internal/model"
)

// Step advances one host's lifecycle with its observation in run runID.
// prev is nil for a host never seen before. now is used for FirstSeen and
// LastSeen. Applying the same run twice is a no-op; prev is never mutated.
//
// Rules (thresholds from cfg):
//   - up resets Misses; down increments it;
//   - inactive: not up and Misses >= InactiveAfterMisses;
//   - unstable: at least UnstableIfFlips up/down transitions among the last
//     Window observations (Flips keeps Window entries);
//   - otherwise up or down per the observation.
func Step(prev *model.HostState, ip netip.Addr, up bool, runID int64, now time.Time, cfg Config) model.HostState {
	var h model.HostState
	if prev != nil {
		h = *prev
		h.Flips = slices.Clone(prev.Flips)
		if n := len(h.Flips); n > 0 && h.Flips[n-1].RunID == runID {
			return h
		}
	} else {
		h = model.HostState{IP: ip.Unmap(), FirstSeen: now, LastSeen: now}
	}
	h.Flips = append(h.Flips, model.Flip{RunID: runID, Up: up})
	if k := keepFlips(cfg); len(h.Flips) > k {
		h.Flips = slices.Clone(h.Flips[len(h.Flips)-k:])
	}
	if up {
		h.Misses = 0
		h.LastSeen = now
	} else {
		h.Misses++
	}
	h.State = Classify(h.Flips, h.Misses, cfg)
	return h
}

// Classify returns the lifecycle state for a flip history and miss count.
func Classify(flips []model.Flip, misses int, cfg Config) model.HostStateKind {
	if len(flips) == 0 {
		return model.HostDown
	}
	last := flips[len(flips)-1]
	if !last.Up && cfg.InactiveAfterMisses > 0 && misses >= cfg.InactiveAfterMisses {
		return model.HostInactive
	}
	if cfg.UnstableIfFlips > 0 && Transitions(windowOf(flips, cfg)) >= cfg.UnstableIfFlips {
		return model.HostUnstable
	}
	if last.Up {
		return model.HostUp
	}
	return model.HostDown
}

// Transitions counts up/down changes between consecutive observations.
func Transitions(flips []model.Flip) int {
	n := 0
	for i := 1; i < len(flips); i++ {
		if flips[i].Up != flips[i-1].Up {
			n++
		}
	}
	return n
}

func keepFlips(cfg Config) int { return max(cfg.Window, 2) }

func windowOf(flips []model.Flip, cfg Config) []model.Flip {
	if k := keepFlips(cfg); len(flips) > k {
		return flips[len(flips)-k:]
	}
	return flips
}

// Advance applies run runID to the hosts in scope and returns their next
// states, sorted by IP. It stamps FirstSeen/LastSeen with the current time;
// use AdvanceAt to supply the time.
func Advance(known []model.HostState, obs []model.HostObs, curr []model.ServiceObs, runID int64, cfg Config) []model.HostState {
	return AdvanceAt(known, obs, curr, runID, time.Now(), cfg)
}

// AdvanceAt is Advance with an explicit clock. known are the current states
// of hosts covered by the run; a known host absent from obs (and without
// services in curr) counts as a miss. A host is up if obs says so or it has
// a service in curr. Hosts seen for the first time are tracked only once
// they are up.
func AdvanceAt(known []model.HostState, obs []model.HostObs, curr []model.ServiceObs, runID int64, now time.Time, cfg Config) []model.HostState {
	up := make(map[netip.Addr]bool)
	for _, o := range obs {
		ip := o.IP.Unmap()
		up[ip] = up[ip] || o.Up
	}
	for _, s := range curr {
		up[s.Key.IP.Unmap()] = true
	}
	out := make([]model.HostState, 0, len(known)+len(up))
	seen := make(map[netip.Addr]bool, len(known))
	for i := range known {
		ip := known[i].IP.Unmap()
		if seen[ip] {
			continue
		}
		seen[ip] = true
		out = append(out, Step(&known[i], ip, up[ip], runID, now, cfg))
	}
	for ip, isUp := range up {
		if isUp && !seen[ip] {
			out = append(out, Step(nil, ip, true, runID, now, cfg))
		}
	}
	slices.SortFunc(out, func(a, b model.HostState) int { return a.IP.Compare(b.IP) })
	return out
}
