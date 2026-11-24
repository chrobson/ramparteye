package safety

import (
	"fmt"
	"time"
)

// Window is a daily time window given as offsets from local midnight, like a
// scan profile's window. End earlier than Start means the window crosses
// midnight; Start equal to End means the whole day.
type Window struct {
	Start, End time.Duration
	Loc        *time.Location // nil = UTC
}

// Contains reports whether t falls inside the window (both ends included).
func (w Window) Contains(t time.Time) bool {
	loc := w.Loc
	if loc == nil {
		loc = time.UTC
	}
	t = t.In(loc)
	off := time.Duration(t.Hour())*time.Hour + time.Duration(t.Minute())*time.Minute +
		time.Duration(t.Second())*time.Second + time.Duration(t.Nanosecond())
	switch {
	case w.Start == w.End:
		return true
	case w.Start < w.End:
		return off >= w.Start && off <= w.End
	default:
		return off >= w.Start || off <= w.End
	}
}

// String renders the window as HH:MM-HH:MM.
func (w Window) String() string {
	hm := func(d time.Duration) string {
		return fmt.Sprintf("%02d:%02d", int(d.Hours())%24, int(d.Minutes())%60)
	}
	return hm(w.Start) + "-" + hm(w.End)
}
