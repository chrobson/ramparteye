package web

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/chrobson/ramparteye/internal/runner"
	"github.com/chrobson/ramparteye/internal/store"
)

// SSE stream tuning. The heartbeat keeps proxies from closing an idle
// stream; the lifetime bounds a connection so an expired session cannot
// keep listening (the client reconnects and is checked again).
const (
	sseHeartbeat   = 15 * time.Second
	sseLifetime    = 30 * time.Minute
	sseWriteTimout = 10 * time.Second
	sseMaxRuns     = 8 // runs kept in the panel of one connection
	sseEventName   = "live"
)

// sseState is the live panel of one connection: the newest event per run,
// oldest first. It is bounded, so a slow reader cannot make it grow.
type sseState struct {
	runs   []LiveRun
	budget int
	names  map[int64]string
}

func (st *sseState) apply(e runner.Event) {
	i := -1
	for j := range st.runs {
		if st.runs[j].RunID == e.RunID {
			i = j
		}
	}
	if i < 0 {
		st.runs = append(st.runs, LiveRun{RunID: e.RunID, Name: st.names[e.RunID], Budget: st.budget})
		i = len(st.runs) - 1
	}
	r := &st.runs[i]
	r.Percent = max(0, min(100, int(e.Progress*100)))
	r.PPS = e.PPS
	r.PPSPct = 0
	if st.budget > 0 {
		r.PPSPct = max(0, min(100, e.PPS*100/st.budget))
	}
	if e.Kind == runner.EventFinished {
		r.Finished, r.Status = true, e.Message
		r.PPS, r.PPSPct = 0, 0
	}
	for len(st.runs) > sseMaxRuns { // drop the oldest finished run, else the oldest
		drop := 0
		for j := range st.runs {
			if st.runs[j].Finished {
				drop = j
				break
			}
		}
		st.runs = append(st.runs[:drop], st.runs[drop+1:]...)
	}
}

// events streams run events as HTML fragments for the dashboard's live
// panel (htmx SSE extension, event "live"). Every fragment is the whole
// panel rendered from a template, so scanned or user text is escaped.
func (s *Server) events(w http.ResponseWriter, r *http.Request) {
	if s.d.Runner == nil {
		http.Error(w, "no scan runner", http.StatusServiceUnavailable)
		return
	}
	rc := http.NewResponseController(w)
	ch, unsubscribe := s.d.Runner.Subscribe()
	defer unsubscribe()

	st := &sseState{budget: s.d.Cfg.MaxRate, names: map[int64]string{}}
	var runs []store.RunSummary
	if rs, err := s.d.Store.Runs(r.Context(), runsLookback); err == nil {
		runs = rs
	}
	for _, rs := range runs {
		st.names[rs.ID] = rs.ConfigName
	}
	st.runs = s.liveSeed(runs)

	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-cache")
	h.Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	if rc.Flush() != nil {
		return // the writer cannot stream
	}

	send := func(data []byte) bool {
		_ = rc.SetWriteDeadline(time.Now().Add(sseWriteTimout))
		if _, err := w.Write(data); err != nil {
			return false
		}
		return rc.Flush() == nil
	}
	sendPanel := func() bool {
		frag, err := s.liveFragment(st.runs)
		if err != nil {
			s.log.Error("render live panel", "err", err)
			return true
		}
		return send(sseMessage(sseEventName, frag))
	}
	if !sendPanel() {
		return
	}
	beat := time.NewTicker(sseHeartbeat)
	defer beat.Stop()
	life := time.NewTimer(sseLifetime)
	defer life.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-life.C:
			return
		case <-beat.C:
			if !send([]byte(": heartbeat\n\n")) {
				return
			}
		case e, ok := <-ch:
			if !ok {
				return
			}
			st.apply(e)
			// Coalesce a burst into one render.
			for drained := false; !drained; {
				select {
				case e, ok := <-ch:
					if !ok {
						return
					}
					st.apply(e)
				default:
					drained = true
				}
			}
			if !sendPanel() {
				return
			}
		}
	}
}

// liveFragment renders the live panel body.
func (s *Server) liveFragment(runs []LiveRun) ([]byte, error) {
	t, ok := s.pages.set["dashboard"]
	if !ok {
		return nil, errors.New("dashboard page not parsed")
	}
	var buf bytes.Buffer
	if err := t.ExecuteTemplate(&buf, "live-runs", runs); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// sseMessage frames data as one SSE message; every line of data gets its
// own "data:" prefix, so a newline can never end the message early.
func sseMessage(event string, data []byte) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "event: %s\n", event)
	text := strings.ReplaceAll(strings.ReplaceAll(string(data), "\r\n", "\n"), "\r", "\n")
	for _, line := range strings.Split(strings.TrimRight(text, "\n"), "\n") {
		b.WriteString("data: ")
		b.WriteString(line)
		b.WriteByte('\n')
	}
	b.WriteByte('\n')
	return b.Bytes()
}
