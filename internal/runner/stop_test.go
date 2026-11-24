package runner

// Stop pauses a run executing in this process, like the end of its window.
// Tests use it to drive that path; production code pauses through Tick.
func (r *Runner) Stop(runID int64) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	a, ok := r.active[runID]
	if ok {
		a.ctl.stop()
	}
	return ok
}
