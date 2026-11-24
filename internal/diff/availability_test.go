package diff

import (
	"testing"
	"time"

	"github.com/ctx42/testing/pkg/assert"
)

// monday is a Monday (2026-11-02) in the given location.
func monday(loc *time.Location, dayOffset, hour, min int) time.Time {
	return time.Date(2026, 11, 2+dayOffset, hour, min, 0, 0, loc)
}

func TestWeekHeatmapBuckets(t *testing.T) {
	runs := []RunPresence{
		{At: monday(time.UTC, 0, 8, 10), Covered: true, Seen: true},
		{At: monday(time.UTC, 0, 8, 40), Covered: true, Seen: false},
	}

	have := ComputeAvailability(runs, time.UTC)

	assert.Equal(t, Cell{Seen: 1, Total: 2}, have.Week[0][8])
	assert.Equal(t, 1, have.Seen)
	assert.Equal(t, 2, have.Total)
	assert.Equal(t, Band{From: 6, To: 12, Seen: 1, Total: 2}, have.ByBand[1])
}

func TestWeekHeatmapUsesLocation(t *testing.T) {
	loc, err := time.LoadLocation("Europe/Warsaw")
	if err != nil {
		t.Skip("tzdata:", err)
	}
	// Sunday 23:30 UTC is Monday 00:30 in Warsaw (UTC+1 in November).
	at := time.Date(2026, 11, 1, 23, 30, 0, 0, time.UTC)

	have := ComputeAvailability([]RunPresence{{At: at, Covered: true, Seen: true}}, loc)

	assert.Equal(t, Cell{Seen: 1, Total: 1}, have.Week[0][0])
}

func TestWeekIndexSunday(t *testing.T) {
	at := monday(time.UTC, 6, 13, 0)

	have := ComputeAvailability([]RunPresence{{At: at, Covered: true, Seen: true}}, time.UTC)

	assert.Equal(t, Cell{Seen: 1, Total: 1}, have.Week[6][13])
}

func TestUncoveredRunsIgnored(t *testing.T) {
	runs := []RunPresence{
		{At: monday(time.UTC, 0, 8, 0), Covered: true, Seen: true},
		{At: monday(time.UTC, 0, 9, 0), Covered: false, Seen: false},
		{At: monday(time.UTC, 0, 10, 0), Covered: false, Seen: true},
	}

	have := ComputeAvailability(runs, time.UTC)

	assert.Equal(t, 1, have.Total)
	assert.Equal(t, 1, have.Seen)
	assert.Equal(t, Cell{}, have.Week[0][9])
	assert.Equal(t, Cell{}, have.Week[0][10])
	assert.Equal(t, PatternAlways, have.Pattern)
}

func TestNoDataPattern(t *testing.T) {
	assert.Equal(t, PatternNoData, ComputeAvailability(nil, time.UTC).Pattern)
	uncovered := []RunPresence{{At: monday(time.UTC, 0, 8, 0), Seen: true}}
	assert.Equal(t, PatternNoData, ComputeAvailability(uncovered, time.UTC).Pattern)
}

func TestPatternStringsAreStable(t *testing.T) {
	assert.Equal(t, "no data", PatternNoData)
	assert.Equal(t, "always", PatternAlways)
	assert.Equal(t, "office hours", PatternOfficeHours)
	assert.Equal(t, "intermittent", PatternIntermittent)
	assert.Equal(t, "irregular", PatternIrregular)
}

// twoWeeks builds hourly-ish runs over 14 days; seen decides presence.
func twoWeeks(seen func(day, hour int) bool) []RunPresence {
	var out []RunPresence
	for d := 0; d < 14; d++ {
		for _, h := range []int{2, 7, 9, 12, 15, 17, 21} {
			out = append(out, RunPresence{At: monday(time.UTC, d, h, 0), Covered: true, Seen: seen(d, h)})
		}
	}
	return out
}

func TestOfficeHoursPattern(t *testing.T) {
	weekday := func(d int) bool { return d%7 < 5 }
	runs := twoWeeks(func(d, h int) bool { return weekday(d) && h >= 7 && h <= 17 })

	have := ComputeAvailability(runs, time.UTC)

	assert.Equal(t, PatternOfficeHours, have.Pattern)
}

func TestAlwaysPattern(t *testing.T) {
	have := ComputeAvailability(twoWeeks(func(int, int) bool { return true }), time.UTC)

	assert.Equal(t, PatternAlways, have.Pattern)
	assert.Equal(t, have.Total, have.Seen)
}

func TestIntermittentPattern(t *testing.T) {
	// Up almost always, with an occasional miss at varying times.
	runs := twoWeeks(func(d, h int) bool { return (d*7+h)%9 != 0 })

	have := ComputeAvailability(runs, time.UTC)

	assert.Equal(t, PatternIntermittent, have.Pattern)
}

func TestIrregularPattern(t *testing.T) {
	// Mostly down with scattered sightings, also outside office hours.
	runs := twoWeeks(func(d, h int) bool { return (d*7+h)%5 == 0 })

	have := ComputeAvailability(runs, time.UTC)

	assert.Equal(t, PatternIrregular, have.Pattern)
}

func TestBandLevel(t *testing.T) {
	assert.Equal(t, "none", Band{}.Level())
	assert.Equal(t, "hi", Band{Seen: 4, Total: 5}.Level())
	assert.Equal(t, "lo", Band{Seen: 1, Total: 5}.Level())
	assert.Equal(t, "mid", Band{Seen: 1, Total: 2}.Level())
}
