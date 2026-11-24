// Package httpfp passively fingerprints HTTP(S) services: status, title,
// headers, cookies, redirect chain, TLS leaf certificate and favicon hash.
//
// Everything read from a scanned host is hostile. Bodies, headers, cookies,
// titles and certificate fields are bounded in size and sanitised to valid
// UTF-8 before they leave this package; escaping for display is the
// consumer's job. Only GET and HEAD are ever sent, and every connection,
// including redirect hops, is checked against the scan scope at dial time.
package httpfp

import (
	"context"
	"crypto/x509"
	"errors"
	"net"
	"net/netip"
	"time"

	"golang.org/x/time/rate"

	"github.com/chrobson/ramparteye/internal/model"
	"github.com/chrobson/ramparteye/internal/scope"
)

// Defaults and hard limits.
const (
	DefaultTimeout      = 10 * time.Second
	DefaultRetries      = 1
	DefaultRetryBackoff = 250 * time.Millisecond
	DefaultRate         = 20 // requests per second
	DefaultBurst        = 5
	DefaultMaxBody      = 1 << 20 // 1 MiB; also the upper bound for Options.MaxBody
	DefaultMaxRedirects = 5
	DefaultUserAgent    = "ramparteye/1.0 (+attack-surface-inventory)"

	maxFaviconBytes = 1 << 20
	maxTitleRunes   = 512
	maxHeaders      = 100
	maxHeaderName   = 256
	maxHeaderValue  = 4 << 10
	maxHeaderValues = 16
	maxCookies      = 100
	maxURL          = 2 << 10
	maxCertField    = 512
	maxSANs         = 100
)

// ErrMethodNotAllowed is returned for any request method but GET and HEAD.
var ErrMethodNotAllowed = errors.New("httpfp: only GET and HEAD are allowed")

// ErrNotAllowed is returned when a connection would go to an address outside
// the scan scope.
var ErrNotAllowed = errors.New("httpfp: address outside the scan scope")

// Prober fetches an endpoint (max 5 redirects, body capped at 1 MiB) and
// records title, headers, cookies, TLS leaf certificate and favicon mmh3.
// Only GET/HEAD requests are ever sent.
type Prober interface {
	Probe(ctx context.Context, ep model.Endpoint) (model.HTTPObs, error)
}

// Resolver resolves a host name to addresses.
type Resolver func(ctx context.Context, host string) ([]netip.Addr, error)

// Options configure an HTTPProber. Zero values select the defaults.
type Options struct {
	// Timeout bounds every single request (connect, TLS, headers, body).
	Timeout time.Duration
	// Retries is how many times a request that timed out or lost its
	// connection is repeated (0 = DefaultRetries, negative = none).
	Retries int
	// RetryBackoff is the pause before a retry (0 = DefaultRetryBackoff).
	RetryBackoff time.Duration
	// Rate and Burst configure the request limiter shared by everything the
	// prober sends (0 = DefaultRate / DefaultBurst).
	Rate  float64
	Burst int
	// MaxBody caps the bytes read from a body (0 or above DefaultMaxBody =
	// DefaultMaxBody). Reaching the cap is not an error.
	MaxBody int64
	// Scope is the allowlist every dialled address must be in. The zero
	// Scope refuses everything.
	Scope scope.Scope

	// Roots is used for the separate certificate verification (nil = system).
	Roots *x509.CertPool
	// Now is the clock used for certificate expiry (nil = time.Now).
	Now func() time.Time
	// SkipFavicon disables favicon fetching.
	SkipFavicon bool
	// LatencySample adds one HEAD request on a warm connection after the
	// probe; the stored response time is the smaller of the two samples.
	LatencySample bool
	// UserAgent sent with every request.
	UserAgent string

	// Resolver resolves redirect target host names (nil = system resolver).
	// Every address it returns must be inside Scope.
	Resolver Resolver
	// DialContext replaces the network dialer (tests). It only ever
	// receives a scope-checked literal "ip:port" address.
	DialContext func(ctx context.Context, network, addr string) (net.Conn, error)
}

// HTTPProber implements Prober.
type HTTPProber struct {
	opt     Options
	limiter *rate.Limiter
}

var _ Prober = (*HTTPProber)(nil)

// New returns a prober with defaults applied.
func New(opt Options) *HTTPProber {
	if opt.Timeout <= 0 {
		opt.Timeout = DefaultTimeout
	}
	switch {
	case opt.Retries == 0:
		opt.Retries = DefaultRetries
	case opt.Retries < 0:
		opt.Retries = 0
	case opt.Retries > 3:
		opt.Retries = 3
	}
	if opt.RetryBackoff <= 0 {
		opt.RetryBackoff = DefaultRetryBackoff
	}
	if opt.Rate <= 0 {
		opt.Rate = DefaultRate
	}
	if opt.Burst <= 0 {
		opt.Burst = DefaultBurst
	}
	if opt.MaxBody <= 0 || opt.MaxBody > DefaultMaxBody {
		opt.MaxBody = DefaultMaxBody
	}
	if opt.UserAgent == "" {
		opt.UserAgent = DefaultUserAgent
	}
	if opt.Now == nil {
		opt.Now = time.Now
	}
	if opt.Resolver == nil {
		opt.Resolver = func(ctx context.Context, host string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		}
	}
	if opt.DialContext == nil {
		d := &net.Dialer{Timeout: opt.Timeout}
		opt.DialContext = d.DialContext
	}
	return &HTTPProber{
		opt:     opt,
		limiter: rate.NewLimiter(rate.Limit(opt.Rate), opt.Burst),
	}
}

// Timeout returns the per-request timeout in effect.
func (p *HTTPProber) Timeout() time.Duration { return p.opt.Timeout }
