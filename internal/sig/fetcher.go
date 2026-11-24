package sig

import (
	"context"
	"errors"
	"net/http"
	"net/url"

	"github.com/chrobson/ramparteye/internal/httpfp"
	"github.com/chrobson/ramparteye/internal/model"
)

// HTTPFetcher adapts httpfp.HTTPProber to Fetcher. Probes go to the
// service's own IP, port and virtual host with the scheme the service was
// first fetched with; the prober checks the scope, allows only GET/HEAD,
// never follows redirects and shares its rate limiter.
type HTTPFetcher struct {
	Prober *httpfp.HTTPProber
}

// NewHTTPFetcher returns a Fetcher backed by p.
func NewHTTPFetcher(p *httpfp.HTTPProber) *HTTPFetcher { return &HTTPFetcher{Prober: p} }

// Fetch implements Fetcher.
func (f *HTTPFetcher) Fetch(ctx context.Context, svc model.ServiceObs, obs model.HTTPObs, req ProbeRequest) (ProbeResponse, error) {
	if f == nil || f.Prober == nil {
		return ProbeResponse{}, errors.New("sig: no prober")
	}
	var hdr http.Header
	if len(req.Headers) > 0 {
		hdr = http.Header{}
		for k, v := range req.Headers {
			hdr.Set(k, v)
		}
	}
	ep := model.Endpoint{ServiceID: svc.ID, Key: svc.Key, Scheme: firstScheme(obs)}
	r, err := f.Prober.FetchPath(ctx, ep, req.Method, req.Path, hdr)
	if err != nil {
		return ProbeResponse{}, err
	}
	return ProbeResponse{Status: r.Status, Header: http.Header(r.Headers), Body: r.Body}, nil
}

// firstScheme is the scheme of the first request of the probe: a redirect
// to https on another port must not move path probes to that port.
func firstScheme(obs model.HTTPObs) string {
	first := obs.URL
	if len(obs.Redirects) > 0 {
		first = obs.Redirects[0].URL
	}
	if u, err := url.Parse(first); err == nil && u.Scheme == "https" {
		return "https"
	}
	return "http"
}
