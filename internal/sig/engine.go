package sig

import (
	"context"
	"net/http"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/chrobson/ramparteye/internal/model"
)

// DefaultProbeTimeout bounds all path probes of one Match call.
const DefaultProbeTimeout = 20 * time.Second

// ProbeRequest is an extra request issued by a path matcher.
type ProbeRequest struct {
	Method  string // GET | HEAD
	Path    string
	Headers map[string]string
}

// ProbeResponse is the result of a ProbeRequest.
type ProbeResponse struct {
	Status int
	Header http.Header
	Body   []byte
}

// Fetcher performs path probes on the service itself. Implementations must
// only send GET/HEAD, stay inside the scan scope and never follow redirects.
type Fetcher interface {
	Fetch(ctx context.Context, svc model.ServiceObs, obs model.HTTPObs, req ProbeRequest) (ProbeResponse, error)
}

// Engine evaluates a set of validated signatures against observations.
type Engine struct {
	mu   sync.RWMutex
	sigs []*Signature

	// Fetcher runs path probes; nil disables them (path matchers never match).
	Fetcher Fetcher
	// ProbeGate, when set, is asked before every path probe that is not
	// already cached for the current Match call; false skips the probe (the
	// matcher does not match). The runner wires it to the per-host path
	// probe budget. nil allows every probe.
	ProbeGate func(host netip.Addr) bool
	// ProbeTimeout bounds all path probes of one Match call
	// (0 = DefaultProbeTimeout).
	ProbeTimeout time.Duration
}

// NewEngine builds an engine. Signatures must come from Parse, Load or
// Validate (which compiles their regular expressions).
func NewEngine(sigs []*Signature, f Fetcher) *Engine {
	return &Engine{sigs: sigs, Fetcher: f}
}

// SetSignatures atomically replaces the active signature set.
func (e *Engine) SetSignatures(sigs []*Signature) {
	e.mu.Lock()
	e.sigs = sigs
	e.mu.Unlock()
}

// Signatures returns the active signature set.
func (e *Engine) Signatures() []*Signature {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return slices.Clone(e.sigs)
}

// Match evaluates every signature against one service and its HTTP
// observation (zero HTTPObs for a non-HTTP service). Path probes are cached
// per call, so several signatures probing the same path cost one request,
// and are bounded by ProbeTimeout. Generic panel detections explained by a
// product detection are dropped (SuppressGeneric).
func (e *Engine) Match(ctx context.Context, svc model.ServiceObs, obs model.HTTPObs) []model.Detection {
	t := e.ProbeTimeout
	if t <= 0 {
		t = DefaultProbeTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, t)
	defer cancel()
	ev := newEvaluator(ctx, svc, obs, e.Fetcher, e.ProbeGate)
	var out []model.Detection
	for _, s := range e.Signatures() {
		if d, ok := ev.detect(s); ok {
			out = append(out, d)
		}
	}
	return SuppressGeneric(out)
}

// GenericPanels are catch-all panel signatures (a password field, /admin).
// They are dropped when a product-specific signature on the same service
// already explains the login form.
var GenericPanels = map[string]bool{"login-page": true, "admin-panel": true}

// productCategories are the categories of signatures that name the
// application behind a web UI (a panel, a device, a CMS, other products
// such as Gitea or GitLab). Servers and frameworks (nginx, PHP) do not: a
// login form behind nginx is still worth reporting.
var productCategories = map[string]bool{"admin-panel": true, "iot": true, "cms": true, "other": true}

// nonProduct are signatures in productCategories that describe a property
// of the service rather than the application (TLS, a directory listing).
var nonProduct = map[string]bool{"tls-expired": true, "tls-self-signed": true, "directory-listing": true}

// IsProduct reports whether a detection identifies the application behind
// a service, which makes a generic panel detection on it redundant.
func IsProduct(d model.Detection) bool {
	return !GenericPanels[d.SignatureID] && !nonProduct[d.SignatureID] && productCategories[d.Category]
}

// SuppressGeneric removes GenericPanels detections when a product-specific
// detection (IsProduct) matched the same service. It filters ds in place.
func SuppressGeneric(ds []model.Detection) []model.Detection {
	if !slices.ContainsFunc(ds, IsProduct) {
		return ds
	}
	out := ds[:0]
	for _, d := range ds {
		if !GenericPanels[d.SignatureID] {
			out = append(out, d)
		}
	}
	return out
}
