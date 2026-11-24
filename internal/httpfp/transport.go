package httpfp

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"

	"github.com/chrobson/ramparteye/internal/safety"
)

// target describes where requests for one endpoint go.
type target struct {
	ip       string // literal IP the endpoint's own host is pinned to
	hostname string // host used in URLs, Host header and SNI (vhost or IP)
}

func endpointTarget(ip, vhost string) target {
	t := target{ip: ip, hostname: ip}
	if vhost != "" {
		t.hostname = vhost
	}
	return t
}

// guard rejects every method but GET and HEAD.
type guard struct{ rt http.RoundTripper }

func (g guard) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return nil, ErrMethodNotAllowed
	}
	return g.rt.RoundTrip(r)
}

// client builds an http.Client that never follows redirects by itself and
// whose every connection goes through the scope-checking dialer.
func (p *HTTPProber) client(t target, tlsCfg *tls.Config) *http.Client {
	if tlsCfg == nil {
		tlsCfg = &tls.Config{}
	}
	tlsCfg.InsecureSkipVerify = true //nolint:gosec // the cert is read and verified separately
	tr := &http.Transport{
		Proxy:                  nil,
		DialContext:            p.dialer(t),
		TLSClientConfig:        tlsCfg,
		TLSHandshakeTimeout:    p.opt.Timeout,
		ResponseHeaderTimeout:  p.opt.Timeout,
		DisableKeepAlives:      true,
		MaxResponseHeaderBytes: 64 << 10,
	}
	return &http.Client{
		// Requests are counted in the safety meter of their context (if any)
		// after the method guard, i.e. only what is actually sent.
		Transport: guard{safety.Transport(tr)},
		Timeout:   p.opt.Timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// dialer returns a DialContext that decides on the address actually dialled:
// the endpoint's own host is pinned to its IP, literal IPs are taken as is
// and names are resolved here. Every candidate must be inside the scope, so
// neither a redirect nor a DNS answer (rebinding included) can lead out of
// it, and the connection goes to the checked address, not to a second lookup.
func (p *HTTPProber) dialer(t target) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		ips, err := p.addrs(ctx, t, host)
		if err != nil {
			return nil, err
		}
		var lastErr error
		for _, ip := range ips {
			conn, err := p.opt.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
			if err == nil {
				return conn, nil
			}
			lastErr = err
		}
		return nil, lastErr
	}
}

// addrs returns the scope-checked addresses for host. A single out-of-scope
// address in a DNS answer rejects the whole answer.
func (p *HTTPProber) addrs(ctx context.Context, t target, host string) ([]netip.Addr, error) {
	var ips []netip.Addr
	switch a, perr := netip.ParseAddr(host); {
	case strings.EqualFold(host, t.hostname):
		a, err := netip.ParseAddr(t.ip)
		if err != nil {
			return nil, err
		}
		ips = []netip.Addr{a}
	case perr == nil:
		ips = []netip.Addr{a}
	default:
		var err error
		if ips, err = p.opt.Resolver(ctx, host); err != nil {
			return nil, err
		}
		if len(ips) == 0 {
			return nil, fmt.Errorf("httpfp: no address for %s", host)
		}
	}
	for i, ip := range ips {
		ips[i] = ip.Unmap().WithZone("")
		if err := p.check(ips[i]); err != nil {
			return nil, err
		}
	}
	return ips, nil
}

// check enforces the scope for one address.
func (p *HTTPProber) check(a netip.Addr) error {
	if !p.opt.Scope.Allows(a) {
		return fmt.Errorf("%w: %s", ErrNotAllowed, a)
	}
	return nil
}

func (p *HTTPProber) wait(ctx context.Context) error {
	return p.limiter.Wait(ctx)
}

// isRefused reports a scope refusal.
func isRefused(err error) bool { return errors.Is(err, ErrNotAllowed) }
