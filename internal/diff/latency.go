package diff

import (
	"strconv"

	"github.com/chrobson/ramparteye/internal/model"
)

// LatencyField is the Field of a "changed" row for the HTTP response time.
const LatencyField = "response_ms"

// LatencyMinDeltaMS is the smallest response time change (in ms) reported.
const LatencyMinDeltaMS = 300

// LatencyChanged reports whether an HTTP response time moved enough between
// two runs to be worth a change row: the difference must exceed both
// LatencyMinDeltaMS and the smaller of the two values (the time at least
// doubled or halved), so ordinary jitter is never reported. A value <= 0
// means "not measured" and never produces a change.
func LatencyChanged(oldMS, newMS int) bool {
	if oldMS <= 0 || newMS <= 0 {
		return false
	}
	lo, hi := min(oldMS, newMS), max(oldMS, newMS)
	return hi-lo > max(LatencyMinDeltaMS, lo)
}

// FormatMS renders a response time for change rows and the UI.
func FormatMS(ms int) string { return strconv.Itoa(ms) + " ms" }

// LatencyChanges returns one "changed" row (Field LatencyField) per service
// present in both runs whose response time changed per LatencyChanged. ms
// maps service ids (of either run) to their measured response time.
func LatencyChanges(prev, curr []model.ServiceObs, ms map[int64]int) []model.Change {
	if len(ms) == 0 {
		return nil
	}
	pm := make(map[model.AssetKey]int64, len(prev))
	for _, s := range prev {
		pm[normKey(s.Key)] = s.ID
	}
	var out []model.Change
	for _, c := range curr {
		k := normKey(c.Key)
		pid, ok := pm[k]
		if !ok {
			continue
		}
		o, n := ms[pid], ms[c.ID]
		if LatencyChanged(o, n) {
			out = append(out, model.Change{
				Kind: model.ChangeChanged, Key: k, Field: LatencyField,
				Old: FormatMS(o), New: FormatMS(n),
			})
		}
	}
	return out
}
