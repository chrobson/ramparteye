package web

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/chrobson/ramparteye/internal/dojo"
	"github.com/chrobson/ramparteye/internal/model"
	"github.com/chrobson/ramparteye/internal/prom"
	"github.com/chrobson/ramparteye/internal/safety"
	"github.com/chrobson/ramparteye/internal/store"
)

const (
	// metricsTTL is how long a rendered scrape is served again, so an
	// aggressive scraper cannot load the database.
	metricsTTL = 10 * time.Second
	// metricsTimeout bounds one collection; it stays below Prometheus'
	// default scrape timeout of 10 s.
	metricsTimeout = 5 * time.Second
)

// Every label value below comes from a fixed list in this file or in the
// model, never from scanned hosts or free text: the cardinality is bounded
// and the endpoint reveals no inventory, only counts.
var (
	runStatuses = []string{store.RunQueued, store.RunRunning, store.RunPaused, store.RunDone,
		store.RunFailed, store.RunCancelled}
	hostStates = []model.HostStateKind{model.HostUp, model.HostDown, model.HostInactive, model.HostUnstable}
	severities = []model.Severity{model.SevInfo, model.SevLow, model.SevMedium, model.SevHigh, model.SevCritical}
	changeKind = []model.ChangeKind{model.ChangeNew, model.ChangeGone, model.ChangeChanged, model.ChangeHostUp,
		model.ChangeHostDown, model.ChangeUnstable}
	checkStatuses = []safety.Status{safety.StatusPass, safety.StatusFail, safety.StatusUnmeasured}
)

// metricsCollector renders GET /metrics: it answers from a cache that is at
// most ttl old, and refreshes it under a lock, so concurrent scrapes share
// one collection.
type metricsCollector struct {
	mon     Monitor
	runner  Runner // nil = no runner
	pusher  Pusher // nil = DefectDojo not configured
	version string
	log     *slog.Logger

	token   [sha256.Size]byte // SHA-256 of the configured token
	ttl     time.Duration
	timeout time.Duration
	now     func() time.Time

	mu   sync.Mutex
	body []byte
	at   time.Time
}

func newMetricsCollector(s *Server, token string) *metricsCollector {
	version := s.d.Version
	if version == "" {
		version = "unknown"
	}
	return &metricsCollector{mon: s.monitor, runner: s.d.Runner, pusher: s.d.Pusher, version: version,
		log: s.log, token: sha256.Sum256([]byte(token)), ttl: metricsTTL, timeout: metricsTimeout, now: s.now}
}

// metrics serves the exposition after the bearer token check. The route
// sits outside the session group: a cookie is no credential here.
func (s *Server) metricsHandler(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	if !s.metrics.authorized(r) {
		s.log.Warn("metrics: request without a valid bearer token", "client", clientIP(r, s.d.Cfg.TrustedProxies))
		h.Set("WWW-Authenticate", "Bearer")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	body, err := s.metrics.render(r.Context())
	if err != nil {
		s.log.Error("metrics: encode", "err", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	h.Set("Content-Type", prom.ContentType)
	_, _ = w.Write(body)
}

// authorized compares the presented token with the configured one in
// constant time (both are hashed first, so the length does not leak).
func (c *metricsCollector) authorized(r *http.Request) bool {
	scheme, tok, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return false
	}
	got := sha256.Sum256([]byte(tok))
	return subtle.ConstantTimeCompare(got[:], c.token[:]) == 1
}

// render returns the cached exposition, collecting a new one when the cache
// is older than ttl. The collection does not end with the request that
// triggered it, so a scraper that hangs up cannot poison the cache.
func (c *metricsCollector) render(ctx context.Context) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if age := now.Sub(c.at); c.body != nil && age >= 0 && age < c.ttl {
		return c.body, nil
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), c.timeout)
	defer cancel()
	body, err := c.collect(ctx)
	if err != nil {
		return nil, err
	}
	c.body, c.at = body, now
	return body, nil
}

// group is a set of metrics fed by the same queries. When one of them
// fails the whole group is left out of the response and
// ramparteye_collector_success reports 0 for it.
type group struct {
	name string
	fn   func(ctx context.Context) ([]prom.Family, error)
}

func (c *metricsCollector) collect(ctx context.Context) ([]byte, error) {
	fams := []prom.Family{gauge("ramparteye_build_info", "Build information; the value is always 1.",
		sample(1, prom.Label{Name: "version", Value: c.version}))}
	if c.runner != nil {
		fams = append(fams, gauge("ramparteye_scan_runs_active", "Scan runs executing in this process now.",
			sample(float64(len(c.runner.ActiveRuns())))))
	}
	var ok []prom.Sample
	for _, g := range []group{{"runs", c.runs}, {"hosts", c.hosts}, {"inventory", c.inventory},
		{"safety", c.safety}, {"defectdojo", c.defectdojo}} {
		f, err := g.fn(ctx)
		up := 1.0
		if err != nil {
			c.log.Error("metrics: collector failed, answering partially", "collector", g.name, "err", err)
			f, up = nil, 0
		}
		fams = append(fams, f...)
		ok = append(ok, sample(up, prom.Label{Name: "collector", Value: g.name}))
	}
	fams = append(fams, prom.Family{Name: "ramparteye_collector_success", Type: prom.Gauge, Samples: ok,
		Help: "1 when the queries of a metric group succeeded; 0 means the group is missing from this response."})
	var b bytes.Buffer
	if err := prom.Write(&b, fams); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func (c *metricsCollector) runs(ctx context.Context) ([]prom.Family, error) {
	counts, err := c.mon.ScanRunCounts(ctx)
	if err != nil {
		return nil, err
	}
	last, err := c.mon.LastFinishedScan(ctx)
	if err != nil {
		return nil, err
	}
	var byStatus []prom.Sample
	for _, st := range runStatuses {
		byStatus = append(byStatus, sample(float64(counts[st]), prom.Label{Name: "status", Value: st}))
	}
	fams := []prom.Family{gauge("ramparteye_scan_runs", "Scan runs by status.", byStatus...)}
	if last != nil {
		fams = append(fams,
			gauge("ramparteye_last_scan_finished_timestamp_seconds",
				"Unix time the latest finished scan (status done) ended.", sample(float64(last.FinishedAt.Unix()))),
			gauge("ramparteye_last_scan_duration_seconds", "Scanning time of the latest finished scan.",
				sample(last.Duration.Seconds())))
	}
	return fams, nil
}

func (c *metricsCollector) hosts(ctx context.Context) ([]prom.Family, error) {
	counts, err := c.mon.HostStateCounts(ctx)
	if err != nil {
		return nil, err
	}
	var out []prom.Sample
	for _, st := range hostStates {
		out = append(out, sample(float64(counts[st]), prom.Label{Name: "state", Value: string(st)}))
	}
	return []prom.Family{gauge("ramparteye_hosts", "Known hosts by state.", out...)}, nil
}

func (c *metricsCollector) inventory(ctx context.Context) ([]prom.Family, error) {
	inv, err := c.mon.LatestRunInventory(ctx)
	if err != nil {
		return nil, err
	}
	var fams []prom.Family
	if inv.RunID != 0 {
		bySev := map[model.Severity]int{}
		for _, d := range inv.Detections {
			// The effective severity is one of the five fixed ones whatever
			// the signature recorded.
			sev := dojo.DetectionSeverity(model.Detection{Category: d.Category,
				Evidence: map[string]string{"severity": d.Severity}})
			bySev[sev] += d.N
		}
		var out []prom.Sample
		for _, sev := range severities {
			out = append(out, sample(float64(bySev[sev]),
				prom.Label{Name: "severity", Value: strings.ToLower(string(sev))}))
		}
		fams = append(fams,
			gauge("ramparteye_latest_run_services", "Services seen in the latest finished run.",
				sample(float64(inv.Services))),
			gauge("ramparteye_latest_run_detections", "Detections in the latest finished run by severity.", out...))
	}
	if inv.DiffRunID != 0 {
		var out []prom.Sample
		for _, k := range changeKind {
			out = append(out, sample(float64(inv.Changes[k]), prom.Label{Name: "kind", Value: string(k)}))
		}
		fams = append(fams, gauge("ramparteye_latest_diff_changes", "Changes of the latest applied diff by kind.", out...))
	}
	return fams, nil
}

func (c *metricsCollector) safety(ctx context.Context) ([]prom.Family, error) {
	id, err := c.mon.LatestReceiptRun(ctx)
	if err != nil || id == 0 {
		return nil, err
	}
	receipt, err := c.mon.SafetyReceipt(ctx, id)
	if errors.Is(err, safety.ErrNoReceipt) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	rep := safety.BuildReport(receipt)
	passed := 0.0
	if rep.Status == safety.ReportOK {
		passed = 1
	}
	var out []prom.Sample
	for _, st := range checkStatuses {
		n := 0
		for _, ch := range rep.Checks {
			if ch.Status == st {
				n++
			}
		}
		out = append(out, sample(float64(n), prom.Label{Name: "status", Value: string(st)}))
	}
	return []prom.Family{
		gauge("ramparteye_safety_receipt_ok", "1 when every check of the safety receipt of the latest finished scan run "+
			"passed, 0 when one failed or was not measured.", sample(passed)),
		gauge("ramparteye_safety_receipt_checks", "Checks of that safety receipt by outcome.", out...),
	}, nil
}

func (c *metricsCollector) defectdojo(ctx context.Context) ([]prom.Family, error) {
	var chip dojo.ChipState
	if c.pusher != nil {
		var err error
		if chip, err = c.pusher.Status(ctx); err != nil {
			return nil, err
		}
	}
	fams := []prom.Family{gauge("ramparteye_defectdojo_configured", "1 when a DefectDojo URL and token are configured.",
		sample(b2f(chip.Configured)))}
	if chip.LastOK != nil {
		fams = append(fams,
			gauge("ramparteye_defectdojo_last_push_ok", "1 when the latest DefectDojo push attempt succeeded "+
				"(skipped pushes ignored); absent before the first push.", sample(b2f(*chip.LastOK))),
			gauge("ramparteye_defectdojo_last_push_timestamp_seconds", "Unix time of the latest DefectDojo push attempt.",
				sample(float64(chip.LastAt.Unix()))))
	}
	return fams, nil
}

func gauge(name, help string, samples ...prom.Sample) prom.Family {
	return prom.Family{Name: name, Help: help, Type: prom.Gauge, Samples: samples}
}

func sample(v float64, labels ...prom.Label) prom.Sample {
	return prom.Sample{Labels: labels, Value: v}
}

func b2f(b bool) float64 {
	if b {
		return 1
	}
	return 0
}
