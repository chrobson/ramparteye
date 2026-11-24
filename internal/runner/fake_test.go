package runner

import (
	"context"
	"errors"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/chrobson/ramparteye/internal/diff"
	"github.com/chrobson/ramparteye/internal/model"
	"github.com/chrobson/ramparteye/internal/safety"
	"github.com/chrobson/ramparteye/internal/scan"
	"github.com/chrobson/ramparteye/internal/store"
)

// fakeStore is an in-memory Store. LeaseChunk emulates FOR UPDATE SKIP
// LOCKED (a chunk goes to exactly one caller) and the chunk methods enforce
// the lease token like the real store.
type fakeStore struct {
	mu       sync.Mutex
	configs  []store.ScanConfig
	targets  map[int64]model.Target
	runs     map[int64]*fakeRun
	chunks   []*fakeChunk
	hosts    []model.HostObs
	services []model.ServiceObs
	leases   map[int64]int // chunk id -> number of leases
	// completeDeadlines are the context deadlines CompleteChunk got.
	completeDeadlines []time.Time
	nextID            int64

	httpObs    map[int64]model.HTTPObs
	legacy     map[int64]store.LegacyTLS
	detections map[int64][]model.Detection
	applied    []int64
	receipts   []safety.Receipt // every saved delta
	failSaves  int              // SaveSafetyReceipt fails this many more times
	probes     map[netip.Addr]int
	sigRows    []store.SignatureRow
	synced     int

	countCalls  int
	countFail   map[int]bool // CountChunks call numbers (1-based) that fail
	finishFails int          // FinishRun fails this many more times
	applyPanic  bool         // ApplyRun panics
	rcptPanic   bool         // SafetyReceipt panics

	cancelReqs map[int64]*int64 // run id -> requested by
	audits     []fakeAudit
	onCancel   func() // called by CancelOpenRuns before its transaction
	cancelFail bool   // CancelOpenRuns fails
}

type fakeAudit struct {
	userID  *int64
	action  string
	entity  string
	details any
}

type fakeRun struct {
	store.RunInfo
	durationMs int64
}

type fakeChunk struct {
	store.Chunk
	status  string
	durMs   int64
	hostsUp int
	lastErr string
}

func newFakeStore() *fakeStore {
	return &fakeStore{
		targets: map[int64]model.Target{}, runs: map[int64]*fakeRun{}, leases: map[int64]int{},
		httpObs: map[int64]model.HTTPObs{}, legacy: map[int64]store.LegacyTLS{},
		detections: map[int64][]model.Detection{}, cancelReqs: map[int64]*int64{},
	}
}

var _ Store = (*fakeStore)(nil)

func (f *fakeStore) id() int64 { f.nextID++; return f.nextID }

func (f *fakeStore) ResetRunning(context.Context) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var n int64
	for _, c := range f.chunks {
		if c.status == store.ChunkRunning {
			c.status = store.ChunkPending
			n++
		}
	}
	for _, r := range f.runs {
		if _, req := f.cancelReqs[r.ID]; req && !finalStatus(r.Status) {
			r.Status = store.RunCancelled
		}
		if r.Status == store.RunRunning {
			r.Status = store.RunPaused
		}
	}
	return n, nil
}

func (f *fakeStore) ScanConfigs(context.Context) ([]store.ScanConfig, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]store.ScanConfig(nil), f.configs...), nil
}

func (f *fakeStore) ScanConfig(_ context.Context, id int64) (store.ScanConfig, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.configs {
		if c.ID == id {
			return c, nil
		}
	}
	return store.ScanConfig{}, store.ErrScanConfigNotFound
}

func (f *fakeStore) ScanTargets(_ context.Context, ids []int64) ([]model.Target, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []model.Target
	for _, id := range ids {
		if t, ok := f.targets[id]; ok {
			out = append(out, t)
		}
	}
	return out, nil
}

func (f *fakeStore) CreateRun(_ context.Context, configID *int64, chunks []netip.Prefix) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	id := f.id()
	f.runs[id] = &fakeRun{RunInfo: store.RunInfo{ID: id, ConfigID: configID, Status: store.RunQueued}}
	for _, p := range chunks {
		f.chunks = append(f.chunks, &fakeChunk{Chunk: store.Chunk{ID: f.id(), RunID: id, Prefix: p}, status: store.ChunkPending})
	}
	return id, nil
}

func (f *fakeStore) LastRun(_ context.Context, configID int64) (*store.RunInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var best *store.RunInfo
	for _, r := range f.runs {
		if r.ConfigID != nil && *r.ConfigID == configID && (best == nil || r.ID > best.ID) {
			ri := r.RunInfo
			best = &ri
		}
	}
	return best, nil
}

func (f *fakeStore) OpenRuns(context.Context) ([]store.RunInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []store.RunInfo
	for _, r := range f.runs {
		if _, req := f.cancelReqs[r.ID]; req && r.Status != store.RunRunning {
			continue
		}
		switch r.Status {
		case store.RunQueued, store.RunRunning, store.RunPaused:
			out = append(out, r.RunInfo)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (f *fakeStore) StartRun(ctx context.Context, runID int64) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	r := f.runs[runID]
	if finalStatus(r.Status) {
		return false, nil
	}
	r.Status = store.RunRunning
	if r.StartedAt == nil {
		t := time.Now()
		r.StartedAt = &t
	}
	return true, nil
}

func (f *fakeStore) LeaseChunk(ctx context.Context, runID int64) (store.Chunk, bool, error) {
	if err := ctx.Err(); err != nil {
		return store.Chunk{}, false, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.chunks {
		if c.RunID == runID && c.status == store.ChunkPending {
			c.status = store.ChunkRunning
			c.Attempts++
			f.leases[c.ID]++
			return c.Chunk, true, nil
		}
	}
	return store.Chunk{}, false, nil
}

// leased returns the chunk of c when c's lease is current.
func (f *fakeStore) leased(c store.Chunk) (*fakeChunk, error) {
	for _, fc := range f.chunks {
		if fc.ID == c.ID {
			if fc.status != store.ChunkRunning || fc.Attempts != c.Attempts {
				return nil, store.ErrLeaseLost
			}
			return fc, nil
		}
	}
	return nil, errors.New("no chunk")
}

func (f *fakeStore) chunk(id int64) *fakeChunk {
	for _, c := range f.chunks {
		if c.ID == id {
			return c
		}
	}
	panic("no chunk")
}

func (f *fakeStore) CompleteChunk(ctx context.Context, c store.Chunk, dur time.Duration, hosts []model.HostObs, svcs []model.ServiceObs) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if dl, ok := ctx.Deadline(); ok {
		f.completeDeadlines = append(f.completeDeadlines, dl)
	}
	fc, err := f.leased(c)
	if err != nil {
		return err
	}
	fc.status = store.ChunkDone
	fc.durMs = dur.Milliseconds()
	for _, h := range hosts {
		if h.Up {
			fc.hostsUp++
		}
	}
	f.hosts = append(f.hosts, hosts...)
	for _, s := range svcs {
		s.ID = f.id()
		f.services = append(f.services, s)
	}
	return nil
}

func (f *fakeStore) ReleaseChunk(_ context.Context, c store.Chunk, reason string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	fc, err := f.leased(c)
	if err != nil {
		return err
	}
	fc.status, fc.lastErr = store.ChunkPending, reason
	return nil
}

func (f *fakeStore) InterruptChunk(_ context.Context, c store.Chunk, reason string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	fc, err := f.leased(c)
	if err != nil {
		return err
	}
	fc.status, fc.lastErr = store.ChunkPending, reason
	fc.Attempts = max(fc.Attempts-1, 0)
	return nil
}

func (f *fakeStore) FailChunk(_ context.Context, c store.Chunk, reason string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	fc, err := f.leased(c)
	if err != nil {
		return err
	}
	fc.status, fc.lastErr = store.ChunkFailed, reason
	return nil
}

func (f *fakeStore) CountChunks(_ context.Context, runID int64) (store.ChunkCounts, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.countCalls++
	if f.countFail[f.countCalls] {
		return store.ChunkCounts{}, errors.New("database unavailable")
	}
	var cc store.ChunkCounts
	for _, c := range f.chunks {
		if c.RunID != runID {
			continue
		}
		switch c.status {
		case store.ChunkPending:
			cc.Pending++
		case store.ChunkRunning:
			cc.Running++
		case store.ChunkDone:
			cc.Done++
		case store.ChunkFailed:
			cc.Failed++
		}
	}
	return cc, nil
}

func (f *fakeStore) FinishRun(_ context.Context, runID int64, status string, active time.Duration) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.finishFails > 0 {
		f.finishFails--
		return false, errors.New("database unavailable")
	}
	r := f.runs[runID]
	if finalStatus(r.Status) {
		return false, nil
	}
	r.Status = status
	r.durationMs += active.Milliseconds()
	return true, nil
}

func (f *fakeStore) CancelOpenRuns(_ context.Context, by *int64) ([]int64, []int64, error) {
	if f.onCancel != nil {
		f.onCancel()
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.cancelFail {
		return nil, nil, errors.New("database unavailable")
	}
	requested, finished := []int64{}, []int64{}
	for _, r := range f.runs {
		switch r.Status {
		case store.RunQueued, store.RunRunning, store.RunPaused:
		default:
			continue
		}
		requested = append(requested, r.ID)
		if _, ok := f.cancelReqs[r.ID]; !ok {
			f.cancelReqs[r.ID] = by
		}
		if r.Status != store.RunRunning {
			r.Status = store.RunCancelled
			finished = append(finished, r.ID)
		}
	}
	sort.Slice(requested, func(i, j int) bool { return requested[i] < requested[j] })
	sort.Slice(finished, func(i, j int) bool { return finished[i] < finished[j] })
	return requested, finished, nil
}

func (f *fakeStore) CancelRequested(_ context.Context, runID int64) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.cancelReqs[runID]
	return ok, nil
}

// requestCancel records a cancel request as another process would.
func (f *fakeStore) requestCancel(runID int64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cancelReqs[runID] = nil
}

func (f *fakeStore) InsertAudit(_ context.Context, userID *int64, action, entity string, details any) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.audits = append(f.audits, fakeAudit{userID: userID, action: action, entity: entity, details: details})
	return nil
}

func (f *fakeStore) RunServices(_ context.Context, runID int64) ([]model.ServiceObs, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []model.ServiceObs
	for _, s := range f.services {
		if s.RunID == runID {
			out = append(out, s)
		}
	}
	return out, nil
}

func (f *fakeStore) RunHostObs(_ context.Context, runID int64) ([]model.HostObs, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []model.HostObs
	for _, h := range f.hosts {
		if h.RunID == runID {
			out = append(out, h)
		}
	}
	return out, nil
}

func (f *fakeStore) SaveHTTPObs(_ context.Context, o model.HTTPObs) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.httpObs[o.ServiceID] = o
	return nil
}

func (f *fakeStore) SaveLegacyTLS(_ context.Context, serviceID int64, r store.LegacyTLS) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.legacy[serviceID] = r
	return nil
}

func (f *fakeStore) ReplaceDetections(_ context.Context, serviceID int64, ds []model.Detection) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.detections[serviceID] = ds
	return nil
}

func (f *fakeStore) ApplyRun(_ context.Context, runID int64, _ diff.Config, _ time.Time) (store.ApplyResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.applyPanic {
		panic("apply exploded")
	}
	for _, id := range f.applied {
		if id == runID {
			return store.ApplyResult{}, store.ErrAlreadyApplied
		}
	}
	f.applied = append(f.applied, runID)
	return store.ApplyResult{RunID: runID}, nil
}

func (f *fakeStore) SaveSafetyReceipt(_ context.Context, r safety.Receipt) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failSaves > 0 {
		f.failSaves--
		return errors.New("database unavailable")
	}
	f.receipts = append(f.receipts, r)
	return nil
}

func (f *fakeStore) SafetyReceipt(_ context.Context, runID int64) (safety.Receipt, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.rcptPanic {
		panic("receipt exploded")
	}
	out := safety.Receipt{RunID: runID}
	found := false
	for _, r := range f.receipts {
		if r.RunID != runID {
			continue
		}
		found = true
		out.NmapInvocations += r.NmapInvocations
		out.NmapPackets += r.NmapPackets
		out.HTTPGet += r.HTTPGet
		out.HTTPHead += r.HTTPHead
		out.PathProbes += r.PathProbes
		out.PathProbesRefused += r.PathProbesRefused
		out.PathProbeWebServices += r.PathProbeWebServices
		out.PathProbeGateCalls += r.PathProbeGateCalls
		out.TargetsChecked += r.TargetsChecked
		out.TargetsOutsideAllowlist += r.TargetsOutsideAllowlist
		out.UncheckedInvocations += r.UncheckedInvocations
		out.PathProbeSignatures = r.PathProbeSignatures
		out.PathProbeSignaturesKnown = out.PathProbeSignaturesKnown || r.PathProbeSignaturesKnown
		out.PathProbeBudget = max(out.PathProbeBudget, r.PathProbeBudget)
		out.ConfiguredMaxRate = max(out.ConfiguredMaxRate, r.ConfiguredMaxRate)
		out.PerWorkerRate = max(out.PerWorkerRate, r.PerWorkerRate)
		out.HTTPRateLimit = max(out.HTTPRateLimit, r.HTTPRateLimit)
		out.TimeWindow = max(out.TimeWindow, r.TimeWindow)
	}
	if !found {
		return out, safety.ErrNoReceipt
	}
	return out, nil
}

func (f *fakeStore) SafetyProbes(context.Context, int64) (map[netip.Addr]int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.probes, nil
}

func (f *fakeStore) Signatures(context.Context) ([]store.SignatureRow, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.sigRows, nil
}

func (f *fakeStore) SyncBuiltinSignatures(_ context.Context, rows []store.SignatureRow) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.synced++
	f.sigRows = rows
	return nil, nil
}

func (f *fakeStore) runStatus(id int64) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.runs[id].Status
}

func (f *fakeStore) setStatus(id int64, status string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.runs[id].Status = status
}

func (f *fakeStore) appliedRuns() []int64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]int64(nil), f.applied...)
}

func (f *fakeStore) auditLog() []fakeAudit {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]fakeAudit(nil), f.audits...)
}

func (f *fakeStore) runCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.runs)
}

func (f *fakeStore) chunksOf(runID int64) []fakeChunk {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []fakeChunk
	for _, c := range f.chunks {
		if c.RunID == runID {
			out = append(out, *c)
		}
	}
	return out
}

func (f *fakeStore) savedReceipts() []safety.Receipt {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]safety.Receipt(nil), f.receipts...)
}

// fakeScanner reports host .10 of every non-single prefix as live with one
// http service on port 80. Single addresses are down. Every call reports one
// metered nmap invocation of 10 packets.
//   - block: prefixes for which Discover waits until ctx ends;
//   - fail: prefixes for which Discover returns an error.
type fakeScanner struct {
	mu        sync.Mutex
	block     map[netip.Prefix]bool
	fail      map[netip.Prefix]bool
	rates     []int
	groups    [][]netip.Prefix           // prefixes of every Discover call
	opts      map[netip.Prefix]scan.Opts // Discover options per prefix
	started   chan netip.Prefix
	ctxs      []context.Context
	discovers int
	services  int
	onCall    func()        // called synchronously by every Discover
	panics    bool          // Discover panics
	delay     time.Duration // Discover takes this long
	inflight  int
	maxFlight int // most concurrent Discover calls
}

func newFakeScanner() *fakeScanner {
	return &fakeScanner{block: map[netip.Prefix]bool{}, fail: map[netip.Prefix]bool{}, opts: map[netip.Prefix]scan.Opts{}}
}

func run(targets []netip.Prefix) scan.Run {
	now := time.Now()
	return scan.Run{Argv: []string{"-sn", "-n"}, Targets: targets, Packets: 10, Elapsed: time.Millisecond,
		Start: now.Add(-time.Millisecond), End: now}
}

func (s *fakeScanner) Discover(ctx context.Context, ps []netip.Prefix, o scan.Opts) (scan.Result, error) {
	s.mu.Lock()
	s.discovers++
	s.rates = append(s.rates, o.MaxRate)
	s.groups = append(s.groups, append([]netip.Prefix(nil), ps...))
	s.ctxs = append(s.ctxs, ctx)
	s.inflight++
	s.maxFlight = max(s.maxFlight, s.inflight)
	panics, delay, onCall := s.panics, s.delay, s.onCall
	block, fail := false, false
	for _, p := range ps {
		s.opts[p] = o
		block = block || s.block[p]
		fail = fail || s.fail[p]
	}
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.inflight--
		s.mu.Unlock()
	}()
	if panics {
		panic("nmap parser exploded")
	}
	time.Sleep(delay)
	if onCall != nil {
		onCall()
	}
	if s.started != nil {
		s.started <- ps[0]
	}
	res := scan.Result{Runs: []scan.Run{run(ps)}}
	if block {
		<-ctx.Done()
		return res, ctx.Err()
	}
	if fail {
		return res, errors.New("nmap exit 1: boom")
	}
	for _, p := range ps {
		if p.IsSingleIP() {
			continue
		}
		b := p.Addr().As4()
		b[3] = 10
		res.Hosts = append(res.Hosts, model.HostObs{IP: netip.AddrFrom4(b), Up: true})
	}
	return res, nil
}

func (s *fakeScanner) Services(_ context.Context, hosts []netip.Addr, _ scan.Opts) (scan.Result, error) {
	s.mu.Lock()
	s.services++
	s.mu.Unlock()
	var ps []netip.Prefix
	res := scan.Result{}
	for _, h := range hosts {
		ps = append(ps, netip.PrefixFrom(h, 32))
		res.Services = append(res.Services, model.ServiceObs{
			Key: model.AssetKey{IP: h, Port: 80, Proto: "tcp"}, Product: "nginx", Banner: "http"})
	}
	res.Runs = []scan.Run{run(ps)}
	return res, nil
}

func (s *fakeScanner) setBlock(p netip.Prefix, v bool) {
	s.mu.Lock()
	s.block[p] = v
	s.mu.Unlock()
}

// contexts returns the contexts of every Discover call.
func (s *fakeScanner) contexts() []context.Context {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]context.Context(nil), s.ctxs...)
}

func (s *fakeScanner) discoverCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.discovers
}

func (s *fakeScanner) discoverGroups() [][]netip.Prefix {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([][]netip.Prefix(nil), s.groups...)
}

// fakeProber answers every endpoint with a fixed observation. With block
// set it waits until ctx ends and records the deadline it was given.
type fakeProber struct {
	mu        sync.Mutex
	obs       model.HTTPObs
	block     bool
	panics    bool
	timeout   time.Duration
	calls     []model.Endpoint
	deadlines []time.Duration // deadline minus call time
}

func (p *fakeProber) Probe(ctx context.Context, ep model.Endpoint) (model.HTTPObs, error) {
	p.mu.Lock()
	p.calls = append(p.calls, ep)
	if dl, ok := ctx.Deadline(); ok {
		p.deadlines = append(p.deadlines, time.Until(dl))
	}
	block := p.block
	o := p.obs
	panics := p.panics
	p.mu.Unlock()
	if panics {
		panic("title parser exploded")
	}
	if block {
		<-ctx.Done()
		return model.HTTPObs{ServiceID: ep.ServiceID}, ctx.Err()
	}
	o.ServiceID = ep.ServiceID
	return o, nil
}

func (p *fakeProber) Timeout() time.Duration { return p.timeout }

func (p *fakeProber) endpoints() []model.Endpoint {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]model.Endpoint(nil), p.calls...)
}
