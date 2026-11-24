package runner

import "time"

// NextWindow returns the scan window relevant at now: the window containing
// now, or else the next one to open. start and end are offsets from local
// midnight in now's location. end < start means the window crosses midnight
// (22:00-06:00); start == end means it is always open (24 h starting at
// start). The window is half-open [from, to).
func NextWindow(now time.Time, start, end time.Duration) (from, to time.Time) {
	start, end = clampDay(start), clampDay(end)
	y, m, d := now.Date()
	at := func(dayOffset int, off time.Duration) time.Time {
		return time.Date(y, m, d+dayOffset, int(off/time.Hour), int(off%time.Hour/time.Minute),
			int(off%time.Minute/time.Second), int(off%time.Second), now.Location())
	}
	endDays := 0
	if end <= start {
		endDays = 1 // crosses midnight, or a full day when start == end
	}
	for off := -1; off <= 1; off++ {
		f, t := at(off, start), at(off+endDays, end)
		if now.Before(t) && !now.Before(f) || now.Before(f) {
			return f, t
		}
	}
	// Unreachable for valid input: tomorrow's window starts after now.
	return at(1, start), at(1+endDays, end)
}

// InWindow reports whether now lies inside the window [start, end).
func InWindow(now time.Time, start, end time.Duration) bool {
	from, to := NextWindow(now, start, end)
	return !now.Before(from) && now.Before(to)
}

func clampDay(d time.Duration) time.Duration {
	return min(max(d, 0), 24*time.Hour-time.Nanosecond)
}
