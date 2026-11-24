// Package diff compares scan runs, tracks host lifecycle and computes
// availability patterns. All functions are pure.
package diff

import (
	"cmp"
	"slices"
	"strconv"

	"github.com/chrobson/ramparteye/internal/model"
)

// Config defines host lifecycle thresholds.
type Config struct {
	InactiveAfterMisses int
	UnstableIfFlips     int
	Window              int
}

// Diff returns the changes of the current run relative to the previous one.
//
// hist holds the host states AFTER the current run has been applied with
// Advance, i.e. the last flip of each host is its observation in the current
// run. Hosts whose last flip belongs to an older run were not in the current
// run's scope and produce no host-level change.
//
// The current run ID is taken from curr (or, if curr is empty, the newest
// flip in hist); the previous run ID from prev (or the second newest flip).
// Output is sorted by (IP, port, proto, vhost) with host-level events first.
func Diff(prev, curr []model.ServiceObs, hist []model.HostState, cfg Config) []model.Change {
	runID, prevRunID := runIDs(prev, curr, hist)
	out := CompareServices(prev, curr)
	out = append(out, HostChanges(hist, runID, cfg)...)
	for i := range out {
		out[i].RunID = runID
		out[i].PrevRunID = prevRunID
	}
	SortChanges(out)
	return out
}

// comparedFields are the fields compared between two observations of the
// same service, in output order.
var comparedFields = []struct {
	name string
	get  func(model.ServiceObs) string
}{
	{"product", func(s model.ServiceObs) string { return s.Product }},
	{"version", func(s model.ServiceObs) string { return s.Version }},
	{"extrainfo", func(s model.ServiceObs) string { return s.ExtraInfo }},
	{"cpe", func(s model.ServiceObs) string { return s.CPE }},
	{"banner", func(s model.ServiceObs) string { return s.Banner }},
}

// CompareServices returns new/gone/changed service changes between two runs,
// keyed by model.AssetKey. A changed service yields one change per differing
// field. RunID/PrevRunID are left zero; output order is unspecified (see
// SortChanges).
func CompareServices(prev, curr []model.ServiceObs) []model.Change {
	pm := make(map[model.AssetKey]model.ServiceObs, len(prev))
	for _, s := range prev {
		pm[normKey(s.Key)] = s
	}
	cm := make(map[model.AssetKey]model.ServiceObs, len(curr))
	for _, s := range curr {
		cm[normKey(s.Key)] = s
	}
	var out []model.Change
	for k, c := range cm {
		p, ok := pm[k]
		if !ok {
			out = append(out, model.Change{Kind: model.ChangeNew, Key: k, New: summary(c)})
			continue
		}
		for _, f := range comparedFields {
			if o, n := f.get(p), f.get(c); o != n {
				out = append(out, model.Change{
					Kind: model.ChangeChanged, Key: k, Field: f.name, Old: o, New: n,
				})
			}
		}
	}
	for k, p := range pm {
		if _, ok := cm[k]; !ok {
			out = append(out, model.Change{Kind: model.ChangeGone, Key: k, Old: summary(p)})
		}
	}
	return out
}

// HostChanges derives host_up/host_down/unstable events of run runID from
// host states that already include that run's observation.
func HostChanges(hist []model.HostState, runID int64, cfg Config) []model.Change {
	var out []model.Change
	for _, h := range hist {
		out = append(out, hostEvents(h, runID, cfg)...)
	}
	return out
}

func hostEvents(h model.HostState, runID int64, cfg Config) []model.Change {
	n := len(h.Flips)
	if n == 0 || h.Flips[n-1].RunID != runID {
		return nil
	}
	key := model.AssetKey{IP: h.IP.Unmap()}
	last := h.Flips[n-1]
	flipped := n == 1 && last.Up || n > 1 && h.Flips[n-2].Up != last.Up
	if !flipped {
		return nil
	}
	var out []model.Change
	if last.Up {
		out = append(out, model.Change{Kind: model.ChangeHostUp, Key: key, New: string(model.HostUp)})
	} else {
		out = append(out, model.Change{
			Kind: model.ChangeHostDown, Key: key,
			Old: string(model.HostUp), New: string(model.HostDown),
		})
	}
	// Report instability whenever an unstable host flips again, so analysts
	// see each flap of a host already marked unstable.
	if h.State == model.HostUnstable {
		out = append(out, model.Change{
			Kind: model.ChangeUnstable, Key: key,
			Field: "flips", New: strconv.Itoa(Transitions(windowOf(h.Flips, cfg))),
		})
	}
	return out
}

// DropUncarried removes "changed" rows whose new value is empty. An import
// file carries only some fields; a field missing from it is unknown, not
// removed.
func DropUncarried(cs []model.Change) []model.Change {
	out := cs[:0]
	for _, c := range cs {
		if c.Kind == model.ChangeChanged && c.New == "" {
			continue
		}
		out = append(out, c)
	}
	return out
}

// ServiceInstability returns an unstable event for every service that
// appeared or disappeared in this run (a new or gone change in cs) and has,
// counting this run, at least cfg.UnstableIfFlips such transitions among the
// last cfg.Window runs. prior holds, per service key, the number of new/gone
// changes recorded in the previous PriorRuns(cfg) runs.
//
// A service on a host reported unstable in cs is skipped: the host-level
// event already explains why its services come and go.
func ServiceInstability(cs []model.Change, prior map[model.AssetKey]int, cfg Config) []model.Change {
	if cfg.UnstableIfFlips <= 0 {
		return nil
	}
	hostUnstable := map[model.AssetKey]bool{}
	for _, c := range cs {
		if c.Kind == model.ChangeUnstable && c.Key.Port == 0 {
			hostUnstable[model.AssetKey{IP: c.Key.IP.Unmap()}] = true
		}
	}
	var out []model.Change
	seen := map[model.AssetKey]bool{}
	for _, c := range cs {
		if c.Kind != model.ChangeNew && c.Kind != model.ChangeGone {
			continue
		}
		k := normKey(c.Key)
		if seen[k] || hostUnstable[model.AssetKey{IP: k.IP}] {
			continue
		}
		seen[k] = true
		if n := prior[k] + 1; n >= cfg.UnstableIfFlips {
			out = append(out, model.Change{
				Kind: model.ChangeUnstable, Key: k, Field: "flips", New: strconv.Itoa(n),
			})
		}
	}
	return out
}

// PriorRuns is the number of earlier runs whose service transitions count
// towards instability. A window of cfg.Window observations holds Window-1
// transitions; the current run's change is one of them.
func PriorRuns(cfg Config) int { return keepFlips(cfg) - 2 }

// SortChanges orders changes by asset key, host-level events first, then by
// kind and field, for stable output.
func SortChanges(cs []model.Change) {
	slices.SortStableFunc(cs, func(a, b model.Change) int {
		return cmp.Or(
			CompareKeys(a.Key, b.Key),
			cmp.Compare(kindOrder(a.Kind), kindOrder(b.Kind)),
			cmp.Compare(fieldOrder(a.Field), fieldOrder(b.Field)),
		)
	})
}

// CompareKeys orders asset keys by IP, port, proto, vhost.
func CompareKeys(a, b model.AssetKey) int {
	return cmp.Or(
		a.IP.Compare(b.IP),
		cmp.Compare(a.Port, b.Port),
		cmp.Compare(a.Proto, b.Proto),
		cmp.Compare(a.VHost, b.VHost),
	)
}

// KindOrder lists change kinds in display order.
var KindOrder = []model.ChangeKind{
	model.ChangeHostUp, model.ChangeHostDown, model.ChangeUnstable,
	model.ChangeNew, model.ChangeGone, model.ChangeChanged,
}

func kindOrder(k model.ChangeKind) int {
	if i := slices.Index(KindOrder, k); i >= 0 {
		return i
	}
	return len(KindOrder)
}

// extraFields are non-nmap fields ordered after the compared ones.
var extraFields = []string{LatencyField, GatewayField, "flips"}

func fieldOrder(f string) int {
	for i, cf := range comparedFields {
		if cf.name == f {
			return i
		}
	}
	if i := slices.Index(extraFields, f); i >= 0 {
		return len(comparedFields) + i
	}
	return len(comparedFields) + len(extraFields)
}

func normKey(k model.AssetKey) model.AssetKey {
	k.IP = k.IP.Unmap()
	return k
}

// summary is a short human description of a service for new/gone changes.
func summary(s model.ServiceObs) string {
	out := s.Product
	if s.Version != "" {
		if out != "" {
			out += " "
		}
		out += s.Version
	}
	return out
}

func runIDs(prev, curr []model.ServiceObs, hist []model.HostState) (runID, prevRunID int64) {
	for _, s := range curr {
		runID = max(runID, s.RunID)
	}
	if runID == 0 {
		for _, h := range hist {
			if n := len(h.Flips); n > 0 {
				runID = max(runID, h.Flips[n-1].RunID)
			}
		}
	}
	for _, s := range prev {
		prevRunID = max(prevRunID, s.RunID)
	}
	if prevRunID == 0 {
		for _, h := range hist {
			for _, f := range h.Flips {
				if f.RunID < runID {
					prevRunID = max(prevRunID, f.RunID)
				}
			}
		}
	}
	return runID, prevRunID
}
