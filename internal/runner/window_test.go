package runner

import (
	"testing"
	"time"

	"github.com/ctx42/testing/pkg/assert"
)

func hm(h, m int) time.Duration { return time.Duration(h)*time.Hour + time.Duration(m)*time.Minute }

func TestNextWindow(t *testing.T) {
	loc := time.FixedZone("CET", 3600)
	day := func(d, h, m int) time.Time { return time.Date(2026, 11, d, h, m, 0, 0, loc) }
	cases := []struct {
		name       string
		now        time.Time
		start, end time.Duration
		from, to   time.Time
		in         bool
	}{
		{"same day, before", day(21, 8, 0), hm(9, 0), hm(17, 0), day(21, 9, 0), day(21, 17, 0), false},
		{"same day, at start", day(21, 9, 0), hm(9, 0), hm(17, 0), day(21, 9, 0), day(21, 17, 0), true},
		{"same day, inside", day(21, 12, 30), hm(9, 0), hm(17, 0), day(21, 9, 0), day(21, 17, 0), true},
		{"same day, at end is outside", day(21, 17, 0), hm(9, 0), hm(17, 0), day(22, 9, 0), day(22, 17, 0), false},
		{"same day, after", day(21, 23, 0), hm(9, 0), hm(17, 0), day(22, 9, 0), day(22, 17, 0), false},
		{"midnight, evening inside", day(21, 23, 0), hm(22, 0), hm(6, 0), day(21, 22, 0), day(22, 6, 0), true},
		{"midnight, early morning inside", day(22, 2, 0), hm(22, 0), hm(6, 0), day(21, 22, 0), day(22, 6, 0), true},
		{"midnight, daytime outside", day(22, 12, 0), hm(22, 0), hm(6, 0), day(22, 22, 0), day(23, 6, 0), false},
		{"midnight, at end", day(22, 6, 0), hm(22, 0), hm(6, 0), day(22, 22, 0), day(23, 6, 0), false},
		{"midnight, just before start", day(22, 21, 59), hm(22, 0), hm(6, 0), day(22, 22, 0), day(23, 6, 0), false},
		{"ends at midnight", day(21, 23, 59), hm(20, 0), 0, day(21, 20, 0), day(22, 0, 0), true},
		{"always open", day(21, 3, 0), hm(4, 0), hm(4, 0), day(20, 4, 0), day(21, 4, 0), true},
		{"always open, at boundary", day(21, 4, 0), hm(4, 0), hm(4, 0), day(21, 4, 0), day(22, 4, 0), true},
		{"month boundary", day(30, 23, 0), hm(22, 0), hm(1, 0), day(30, 22, 0), time.Date(2026, 12, 1, 1, 0, 0, 0, loc), true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			from, to := NextWindow(c.now, c.start, c.end)
			assert.Time(t, c.from, from)
			assert.Time(t, c.to, to)
			assert.Equal(t, c.in, InWindow(c.now, c.start, c.end))
			assert.True(t, to.After(from))
		})
	}
}

func TestNextWindowDST(t *testing.T) {
	loc, err := time.LoadLocation("Europe/Warsaw")
	if err != nil {
		t.Skip("no tzdata")
	}
	// 2026-03-29: clocks jump 02:00 -> 03:00. A 01:00-04:00 window is 2 h long.
	from, to := NextWindow(time.Date(2026, 3, 29, 1, 30, 0, 0, loc), hm(1, 0), hm(4, 0))
	assert.Equal(t, 2*time.Hour, to.Sub(from))
}
