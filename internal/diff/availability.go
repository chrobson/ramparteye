package diff

import "time"

// RunPresence is one run's verdict about an asset: when the run started,
// whether the run covered the asset (it was in the run's scope) and whether
// the asset was seen. Uncovered runs say nothing about availability.
type RunPresence struct {
	At      time.Time
	Covered bool
	Seen    bool
}

// Cell is one weekday/hour bucket of the weekly heatmap.
type Cell struct{ Seen, Total int }

// Band is a six-hour time-of-day band [From, To) with its counts.
type Band struct {
	From, To    int
	Seen, Total int
}

// Level classifies the band for shading: none (no runs), hi (>= 80%),
// lo (<= 20%) or mid.
func (b Band) Level() string {
	switch {
	case b.Total == 0:
		return "none"
	case b.Seen*5 >= b.Total*4:
		return "hi"
	case b.Seen*5 <= b.Total:
		return "lo"
	}
	return "mid"
}

// Availability patterns returned by ComputeAvailability.
const (
	PatternNoData       = "no data"
	PatternAlways       = "always"
	PatternOfficeHours  = "office hours"
	PatternIntermittent = "intermittent"
	PatternIrregular    = "irregular"
)

// Office hours are Monday to Friday, local hours 07 through 17 inclusive.
const (
	officeFirstHour = 7
	officeLastHour  = 17
	// minPerSide is the number of covered runs inside and outside office
	// hours needed before the office-hours pattern can be claimed.
	minPerSide = 2
)

// Availability summarises the covering runs of one asset.
type Availability struct {
	Seen, Total int
	Pattern     string
	ByBand      [4]Band     // 00-06, 06-12, 12-18, 18-24 local time
	Week        [7][24]Cell // [weekday Monday=0][hour 0-23] in the given location
}

// ComputeAvailability buckets covered runs by local weekday and hour in loc
// (nil means UTC) and classifies the asset:
//   - "no data": no covered runs;
//   - "always": seen in every covered run;
//   - "office hours": seen in at least 80% of the runs inside Mon-Fri
//     07-17 and in at most 20% of the runs outside it, with at least two
//     runs on each side;
//   - "intermittent": seen in at least half of the runs, no time pattern;
//   - "irregular": everything else, including never seen.
func ComputeAvailability(runs []RunPresence, loc *time.Location) Availability {
	if loc == nil {
		loc = time.UTC
	}
	var a Availability
	for i := range a.ByBand {
		a.ByBand[i].From, a.ByBand[i].To = i*6, i*6+6
	}
	var in, out Cell
	for _, r := range runs {
		if !r.Covered {
			continue
		}
		t := r.At.In(loc)
		wd := (int(t.Weekday()) + 6) % 7 // Monday = 0
		h := t.Hour()
		cell := &a.Week[wd][h]
		band := &a.ByBand[h/6]
		side := &out
		if wd < 5 && h >= officeFirstHour && h <= officeLastHour {
			side = &in
		}
		for _, c := range []*Cell{cell, side} {
			c.Total++
			if r.Seen {
				c.Seen++
			}
		}
		band.Total++
		a.Total++
		if r.Seen {
			band.Seen++
			a.Seen++
		}
	}
	switch {
	case a.Total == 0:
		a.Pattern = PatternNoData
	case a.Seen == a.Total:
		a.Pattern = PatternAlways
	case in.Total >= minPerSide && out.Total >= minPerSide &&
		in.Seen*5 >= in.Total*4 && out.Seen*5 <= out.Total:
		a.Pattern = PatternOfficeHours
	case a.Seen*2 >= a.Total:
		a.Pattern = PatternIntermittent
	default:
		a.Pattern = PatternIrregular
	}
	return a
}
