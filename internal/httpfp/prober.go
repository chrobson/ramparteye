package httpfp

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/chrobson/ramparteye/internal/model"
)

// response is a single fetched resource.
type response struct {
	status  int
	header  http.Header
	cookies []*http.Cookie
	body    []byte
	tls     *tls.ConnectionState
	// duration of the successful attempt: connect, TLS, headers and body.
	duration time.Duration
}

// BaseURL returns scheme://host:port/ for an endpoint.
func BaseURL(ep model.Endpoint) string {
	scheme := ep.Scheme
	if scheme == "" {
		scheme = "http"
	}
	host := ep.Key.VHost
	if host == "" {
		host = ep.Key.IP.Unmap().String()
	}
	u := url.URL{
		Scheme: scheme,
		Host:   net.JoinHostPort(host, strconv.Itoa(int(ep.Key.Port))),
		Path:   "/",
	}
	return u.String()
}

// fetch performs one GET/HEAD request without following redirects. The body
// is read up to limit bytes; reaching the limit is not an error.
func (p *HTTPProber) fetch(ctx context.Context, c *http.Client, method, rawURL string, limit int64) (*response, error) {
	return p.fetchHeader(ctx, c, method, rawURL, limit, nil)
}

// fetchHeader is fetch with extra request headers (already vetted by the
// caller); they never replace the User-Agent.
func (p *HTTPProber) fetchHeader(ctx context.Context, c *http.Client, method, rawURL string, limit int64, hdr http.Header) (*response, error) {
	if method != http.MethodGet && method != http.MethodHead {
		return nil, ErrMethodNotAllowed
	}
	if err := p.wait(ctx); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, method, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "text/html,application/xhtml+xml,*/*;q=0.8")
	for k, vs := range hdr {
		req.Header[http.CanonicalHeaderKey(k)] = append([]string(nil), vs...)
	}
	req.Header.Set("User-Agent", p.opt.UserAgent)
	start := time.Now()
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit))
	if err != nil && len(body) == 0 {
		return nil, err
	}
	return &response{
		status:   resp.StatusCode,
		header:   resp.Header,
		cookies:  resp.Cookies(),
		body:     body,
		tls:      resp.TLS,
		duration: time.Since(start),
	}, nil
}

// fetchRetry is fetch with Options.Retries retries after transient errors.
func (p *HTTPProber) fetchRetry(ctx context.Context, c *http.Client, method, rawURL string, limit int64, hdr http.Header) (*response, error) {
	resp, err := p.fetchHeader(ctx, c, method, rawURL, limit, hdr)
	for i := 0; i < p.opt.Retries && err != nil && retryable(ctx, rawURL, err); i++ {
		t := time.NewTimer(p.opt.RetryBackoff)
		select {
		case <-ctx.Done():
			t.Stop()
			return nil, err
		case <-t.C:
		}
		resp, err = p.fetchHeader(ctx, c, method, rawURL, limit, hdr)
	}
	return resp, err
}

// retryable reports transient request errors worth one more attempt.
func retryable(ctx context.Context, rawURL string, err error) bool {
	if ctx.Err() != nil || isRefused(err) || errors.Is(err, ErrMethodNotAllowed) {
		return false
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return false // nothing listens: retrying cannot help
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return true
	}
	// Handshake failures over TLS are handled by the legacy-TLS retry.
	if strings.HasPrefix(rawURL, "https:") && isTLSHandshakeError(err) {
		return false
	}
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, syscall.ECONNRESET) || strings.Contains(err.Error(), "connection reset")
}

// Probe implements Prober. The first request goes to the endpoint's own IP;
// redirects are followed up to 5 hops, each hop re-checked against the scope
// when it is dialled. A hop that cannot be followed (out of scope, other
// port, non-HTTP, unreachable) is recorded with status 0 and ends the chain.
func (p *HTTPProber) Probe(ctx context.Context, ep model.Endpoint) (model.HTTPObs, error) {
	obs := model.HTTPObs{ServiceID: ep.ServiceID}
	if !ep.Key.IP.IsValid() {
		return obs, errors.New("httpfp: endpoint without IP")
	}
	if ep.Scheme != "" && ep.Scheme != "http" && ep.Scheme != "https" {
		return obs, fmt.Errorf("httpfp: unsupported scheme %q", ep.Scheme)
	}
	ip := ep.Key.IP.Unmap()
	if err := p.check(ip); err != nil {
		return obs, err
	}
	t := endpointTarget(ip.String(), ep.Key.VHost)
	c := p.client(t, nil)
	defer func() { c.CloseIdleConnections() }()
	legacyTried := false

	cur := BaseURL(ep)
	obs.URL = cur
	cookies := map[string]model.Cookie{}
	var order []string
	var last *response
	var tlsState *tls.ConnectionState
	for {
		resp, err := p.fetchRetry(ctx, c, http.MethodGet, cur, p.opt.MaxBody, nil)
		if err != nil && !legacyTried && ctx.Err() == nil && !isRefused(err) &&
			strings.HasPrefix(cur, "https:") && isTLSHandshakeError(err) {
			// Old devices often speak only TLS 1.0/1.1 or RSA-kex/3DES suites,
			// which Go no longer offers by default: retry once with them.
			legacyTried = true
			c.CloseIdleConnections()
			c = p.client(t, legacyClientConfig())
			resp, err = p.fetch(ctx, c, http.MethodGet, cur, p.opt.MaxBody)
		}
		if err != nil {
			if last == nil {
				return obs, fmt.Errorf("httpfp: GET %s: %w", cur, err)
			}
			// A redirect target that cannot be reached: show where the chain
			// leads, keep what the earlier hops gave.
			if len(obs.Redirects) < DefaultMaxRedirects+1 {
				obs.Redirects = append(obs.Redirects, model.Redirect{URL: clean(cur, maxURL)})
			}
			break
		}
		last = resp
		obs.URL = clean(cur, maxURL)
		if obs.ResponseMS == 0 {
			// The first hop answers for this service (later hops may be
			// another port after a redirect).
			obs.ResponseMS = max(1, int(resp.duration.Milliseconds()))
		}
		// Only the first hop is this service; a plain-http service that
		// redirects to https must not inherit the certificate of port 443.
		if resp.tls != nil && tlsState == nil && len(obs.Redirects) == 0 {
			tlsState = resp.tls
		}
		for _, ck := range resp.cookies {
			if _, seen := cookies[ck.Name]; !seen {
				if len(order) >= maxCookies {
					continue
				}
				order = append(order, ck.Name)
			}
			cookies[ck.Name] = model.Cookie{
				Name:     clean(ck.Name, maxHeaderName),
				Secure:   ck.Secure,
				HTTPOnly: ck.HttpOnly,
				SameSite: sameSite(ck.SameSite),
			}
		}
		if !isRedirect(resp.status) || len(obs.Redirects) >= DefaultMaxRedirects {
			break // done, or hop limit reached: the last response stays a 3xx
		}
		// Each recorded hop is the redirecting URL with its status; the
		// Location it pointed to becomes the next hop (or obs.URL).
		obs.Redirects = append(obs.Redirects, model.Redirect{URL: clean(cur, maxURL), Status: resp.status})
		loc := resp.header.Get("Location")
		next, ok := resolveRedirect(cur, loc)
		if !ok {
			if loc != "" && len(obs.Redirects) < DefaultMaxRedirects+1 {
				obs.Redirects = append(obs.Redirects, model.Redirect{URL: clean(absOrRaw(cur, loc), maxURL)})
			}
			break
		}
		cur = next
	}

	obs.Status = last.status
	obs.Headers = cleanHeaders(last.header)
	for _, n := range order {
		obs.Cookies = append(obs.Cookies, cookies[n])
	}
	obs.Body = last.body
	sum := sha256.Sum256(last.body)
	obs.BodySHA256 = hex.EncodeToString(sum[:])
	obs.Title = ExtractTitle(last.body)
	if tlsState != nil {
		obs.TLS = p.tlsInfo(tlsState, t.hostname)
	}
	if !p.opt.SkipFavicon {
		if h, ok := p.favicon(ctx, c, obs.URL, last.body, t.hostname); ok {
			obs.FaviconMMH3 = &h
		}
	}
	// The first request often pays for a cold start; a warm HEAD to the first
	// hop gives a steadier sample and the smaller of the two is stored. An
	// injected delay slows every response, so it still shows.
	if p.opt.LatencySample && obs.ResponseMS > 0 {
		if r, err := p.fetch(ctx, c, http.MethodHead, BaseURL(ep), 0); err == nil {
			obs.ResponseMS = min(obs.ResponseMS, max(1, int(r.duration.Milliseconds())))
		}
	}
	return obs, nil
}

func isRedirect(code int) bool {
	switch code {
	case 301, 302, 303, 307, 308:
		return true
	}
	return false
}

func sameSite(s http.SameSite) string {
	switch s {
	case http.SameSiteLaxMode:
		return "Lax"
	case http.SameSiteStrictMode:
		return "Strict"
	case http.SameSiteNoneMode:
		return "None"
	}
	return ""
}

func absOrRaw(base, loc string) string {
	b, err := url.Parse(base)
	if err != nil {
		return loc
	}
	r, err := url.Parse(loc)
	if err != nil {
		return loc
	}
	return b.ResolveReference(r).String()
}

// resolveRedirect resolves loc against base. Only http/https targets are
// followed, and the port may only stay the same or change to the default port
// of the new scheme (http://h:8080 -> https://h/), so a redirect cannot aim
// an HTTP request at an unrelated service. Whether the host is in scope is
// decided when it is dialled.
func resolveRedirect(base, loc string) (string, bool) {
	if loc == "" {
		return "", false
	}
	b, err := url.Parse(base)
	if err != nil {
		return "", false
	}
	r, err := url.Parse(loc)
	if err != nil {
		return "", false
	}
	u := b.ResolveReference(r)
	if (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return "", false
	}
	if effectivePort(u) != effectivePort(b) && u.Port() != "" && u.Port() != defaultPort(u.Scheme) {
		return "", false
	}
	u.Fragment = ""
	return u.String(), true
}

func defaultPort(scheme string) string {
	if scheme == "https" {
		return "443"
	}
	return "80"
}

func effectivePort(u *url.URL) string {
	if p := u.Port(); p != "" {
		return p
	}
	return defaultPort(u.Scheme)
}

// favicon tries <link rel=icon> targets (same host only) then /favicon.ico.
func (p *HTTPProber) favicon(ctx context.Context, c *http.Client, pageURL string, body []byte, host string) (int32, bool) {
	var cands []string
	add := func(ref string) {
		u, ok := resolveRedirect(pageURL, ref)
		if !ok {
			return
		}
		if pu, err := url.Parse(u); err != nil || !strings.EqualFold(pu.Hostname(), host) {
			return
		}
		cands = append(cands, u)
	}
	for _, h := range FaviconLinks(body) {
		add(h)
		if len(cands) == 2 {
			break
		}
	}
	add("/favicon.ico")
	seen := map[string]bool{}
	for _, u := range cands {
		if seen[u] {
			continue
		}
		seen[u] = true
		resp, err := p.fetch(ctx, c, http.MethodGet, u, maxFaviconBytes)
		if err != nil || resp.status != http.StatusOK || len(resp.body) == 0 {
			continue
		}
		if looksLikeHTML(resp.header.Get("Content-Type"), resp.body) {
			continue // soft-404 page, not an icon
		}
		return FaviconHash(resp.body), true
	}
	return 0, false
}
