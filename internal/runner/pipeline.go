package runner

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/chrobson/ramparteye/internal/httpfp"
	"github.com/chrobson/ramparteye/internal/model"
	"github.com/chrobson/ramparteye/internal/safety"
	"github.com/chrobson/ramparteye/internal/sig"
	"github.com/chrobson/ramparteye/internal/store"
)

// probeDeadlineFactor bounds one endpoint probe (redirects, favicon,
// latency sample, retries) to this many per-request timeouts.
const probeDeadlineFactor = 3

// legacyProber is implemented by *httpfp.HTTPProber.
type legacyProber interface {
	ProbeLegacyTLS(ctx context.Context, ep model.Endpoint) (httpfp.LegacyTLS, error)
}

// postProcess runs after every chunk of a run is finished: each HTTP(S)
// service is fingerprinted (GET/HEAD only), signatures are matched on every
// service, and the run is compared with the previous one (diff and host
// states). ctx carries the run's safety meter.
func (r *Runner) postProcess(ctx context.Context, s *session) error {
	svcs, err := r.st.RunServices(ctx, s.runID)
	if err != nil {
		return fmt.Errorf("load services: %w", err)
	}
	names, err := r.hostnames(ctx, s)
	if err != nil {
		return err
	}
	eng := r.runEngine(s.meter)
	if eng != nil {
		n := 0
		for _, sg := range eng.Signatures() {
			if sg.PathProbe {
				n++
			}
		}
		s.meter.SetPathSignatures(n)
	}

	var (
		mu   sync.Mutex
		errs error
		done atomic.Int64
		wg   sync.WaitGroup
	)
	jobs := make(chan model.ServiceObs)
	for range r.cfg.ProbeWorkers {
		wg.Go(func() {
			for svc := range jobs {
				if err := r.service(ctx, s, eng, svc, names[svc.Key.IP]); err != nil {
					mu.Lock()
					errs = errors.Join(errs, fmt.Errorf("%s:%d: %w", svc.Key.IP, svc.Key.Port, err))
					mu.Unlock()
				}
				n := done.Add(1)
				r.publish(Event{RunID: s.runID, Kind: EventProgress, PPS: int(s.meter.Snapshot().PPS),
					Progress: scanShare + (1-scanShare)*float64(n)/float64(len(svcs)+1)})
			}
		})
	}
	for _, svc := range svcs {
		jobs <- svc
	}
	close(jobs)
	wg.Wait()
	s.log.Info("fingerprinting done", "services", len(svcs))

	if _, err := r.st.ApplyRun(ctx, s.runID, r.cfg.Unstable, r.cfg.Now()); err != nil && !errors.Is(err, store.ErrAlreadyApplied) {
		errs = errors.Join(errs, fmt.Errorf("apply diff: %w", err))
	}
	return errs
}

// hostnames returns the names each address of the run is known by: the
// domain targets resolved in this session and the stored host observations.
func (r *Runner) hostnames(ctx context.Context, s *session) (map[netip.Addr][]string, error) {
	out := map[netip.Addr][]string{}
	for a, ns := range s.hostnames {
		out[a] = slices.Clone(ns)
	}
	hosts, err := r.st.RunHostObs(ctx, s.runID)
	if err != nil {
		return nil, fmt.Errorf("load hosts: %w", err)
	}
	for _, h := range hosts {
		if h.Hostname != "" && !slices.Contains(out[h.IP], h.Hostname) {
			out[h.IP] = append(out[h.IP], h.Hostname)
		}
	}
	return out, nil
}

// runEngine returns a copy of the shared engine for one run: its path
// probes use the run's HTTP prober and go through the run's per-host probe
// budget. nil when there is no engine.
func (r *Runner) runEngine(m *safety.Meter) *sig.Engine {
	if r.eng == nil {
		return nil
	}
	f := r.eng.Fetcher
	if hp, ok := r.fp.(*httpfp.HTTPProber); ok {
		f = sig.NewHTTPFetcher(hp)
	}
	e := sig.NewEngine(r.eng.Signatures(), f)
	e.ProbeTimeout = r.eng.ProbeTimeout
	e.ProbeGate = func(h netip.Addr) bool { return m.ProbeGate(h.Unmap().WithZone("")) }
	return e
}

// service fingerprints one service, matches the signatures on it and its
// virtual hosts, and stores the results.
func (r *Runner) service(ctx context.Context, s *session, eng *sig.Engine, svc model.ServiceObs, vhosts []string) error {
	scheme := HTTPScheme(svc)
	web := scheme != "" && r.fp != nil
	var obs model.HTTPObs
	if web {
		var o model.HTTPObs
		var err error
		o, scheme, err = r.probeScheme(ctx, model.Endpoint{ServiceID: svc.ID, Key: svc.Key, Scheme: scheme})
		if err != nil {
			s.log.Debug("http probe failed", "service", svc.Key.IP, "port", svc.Key.Port, "err", err)
		}
		if o.Status != 0 || o.TLS != nil {
			obs = o
			if err := r.st.SaveHTTPObs(ctx, obs); err != nil {
				return fmt.Errorf("save http observation: %w", err)
			}
			if err := r.legacyTLS(ctx, svc, scheme); err != nil {
				return err
			}
		}
	}
	if eng == nil {
		return nil
	}
	if svc.Key.VHost != "" {
		vhosts = nil
	}
	if web {
		s.meter.AddWebServices(1 + len(vhosts))
	}
	dets := eng.Match(ctx, svc, obs)
	if web && len(vhosts) > 0 {
		// Names the address is known by are probed as virtual hosts: a
		// staging vhost on a shared IP is otherwise invisible. Detections
		// belong to the address' service.
		for _, h := range vhosts {
			vs := svc
			vs.Key.VHost = h
			vo, err := r.probe(ctx, model.Endpoint{ServiceID: svc.ID, Key: vs.Key, Scheme: scheme})
			if err != nil && vo.Status == 0 {
				vo = model.HTTPObs{ServiceID: svc.ID}
			}
			dets = mergeDetections(dets, eng.Match(ctx, vs, vo))
		}
		dets = sig.SuppressGeneric(dets)
	}
	for i := range dets {
		dets[i].ServiceID = svc.ID
	}
	if err := r.st.ReplaceDetections(ctx, svc.ID, dets); err != nil {
		return fmt.Errorf("save detections: %w", err)
	}
	return nil
}

// legacyTLS records whether an https service still accepts TLS 1.0/1.1.
func (r *Runner) legacyTLS(ctx context.Context, svc model.ServiceObs, scheme string) error {
	lp, ok := r.fp.(legacyProber)
	if !ok || scheme != "https" {
		return nil
	}
	pctx, cancel := context.WithTimeout(ctx, probeDeadlineFactor*r.probeTimeout())
	defer cancel()
	lt, err := lp.ProbeLegacyTLS(pctx, model.Endpoint{ServiceID: svc.ID, Key: svc.Key, Scheme: scheme})
	if err != nil {
		return nil
	}
	if err := r.st.SaveLegacyTLS(ctx, svc.ID, store.LegacyTLS(lt)); err != nil {
		return fmt.Errorf("save legacy tls: %w", err)
	}
	return nil
}

// probeTimeout is the prober's per-request timeout.
func (r *Runner) probeTimeout() time.Duration {
	if t, ok := r.fp.(interface{ Timeout() time.Duration }); ok && t.Timeout() > 0 {
		return t.Timeout()
	}
	return r.cfg.HTTPTimeout
}

// probe fetches one endpoint within an overall deadline of 3 per-request
// timeouts, so a host trickling bytes cannot hold the pipeline.
func (r *Runner) probe(ctx context.Context, ep model.Endpoint) (model.HTTPObs, error) {
	pctx, cancel := context.WithTimeout(ctx, probeDeadlineFactor*r.probeTimeout())
	defer cancel()
	return r.fp.Probe(pctx, ep)
}

// probeScheme probes ep and, when the scheme nmap suggested looks wrong, the
// other one, returning the observation kept and its scheme:
//   - a port labelled plain http that does not answer HTTP is retried over
//     TLS (nmap sometimes misses TLS);
//   - a port labelled https whose TLS answer is an empty 404 is retried over
//     plain http (some servers route only plain HTTP on a port that also
//     completes a TLS handshake).
func (r *Runner) probeScheme(ctx context.Context, ep model.Endpoint) (model.HTTPObs, string, error) {
	o, err := r.probe(ctx, ep)
	switch {
	case err != nil && ep.Scheme == "http" && o.Status == 0:
		alt := ep
		alt.Scheme = "https"
		if o2, err2 := r.probe(ctx, alt); err2 == nil || o2.Status != 0 {
			return o2, "https", err2
		}
	case err == nil && ep.Scheme == "https" && o.Status == 404 && o.Title == "":
		alt := ep
		alt.Scheme = "http"
		if o2, err2 := r.probe(ctx, alt); err2 == nil && o2.Status != 0 && o2.Status != 404 {
			return o2, "http", nil
		}
	}
	return o, ep.Scheme, err
}

// mergeDetections adds b to a; for a signature in both, the more confident
// detection wins.
func mergeDetections(a, b []model.Detection) []model.Detection {
	idx := make(map[string]int, len(a))
	for i, d := range a {
		idx[d.SignatureID] = i
	}
	for _, d := range b {
		if i, ok := idx[d.SignatureID]; ok {
			if d.Confidence > a[i].Confidence {
				a[i] = d
			}
			continue
		}
		idx[d.SignatureID] = len(a)
		a = append(a, d)
	}
	return a
}

// webPorts are probed over HTTP even when nmap could not name the service.
var webPorts = map[uint16]string{
	80: "http", 81: "http", 3000: "http", 5000: "http", 8000: "http", 8008: "http",
	8080: "http", 8081: "http", 8088: "http", 8222: "http", 8888: "http", 9000: "http",
	443: "https", 8443: "https", 9443: "https",
}

// HTTPScheme returns "http" or "https" for a service worth an HTTP probe and
// "" otherwise. The nmap service name is stored in Banner ("ssl/http").
func HTTPScheme(s model.ServiceObs) string {
	if s.Key.Proto != "" && s.Key.Proto != "tcp" {
		return ""
	}
	b := strings.ToLower(strings.TrimSuffix(s.Banner, "?"))
	switch {
	case strings.HasPrefix(b, "ssl/http"), strings.HasPrefix(b, "https"):
		return "https"
	case strings.HasPrefix(b, "http"):
		if s.Key.Port == 443 || s.Key.Port == 8443 || s.Key.Port == 9443 {
			return "https"
		}
		return "http"
	case b == "" || b == "unknown" || b == "tcpwrapped" || b == "ppp" || b == "hbci" || b == "ssl/unknown" || b == "ssl":
		tls := strings.HasPrefix(b, "ssl")
		if sch, ok := webPorts[s.Key.Port]; ok {
			if tls {
				return "https"
			}
			return sch
		}
		if tls {
			return "https"
		}
	}
	return ""
}
