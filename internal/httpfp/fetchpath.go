package httpfp

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/chrobson/ramparteye/internal/model"
)

// Path probe limits.
const (
	maxProbePath    = 256
	maxProbeHeaders = 8
	maxProbeHdrVal  = 256
)

var (
	// ErrBadPath is returned for a probe path that is not a plain absolute
	// path on the endpoint itself.
	ErrBadPath = errors.New("httpfp: invalid probe path")
	// ErrBadHeader is returned for a probe request header that is not allowed.
	ErrBadHeader = errors.New("httpfp: probe header not allowed")
)

// encodedCtlRe matches percent-encoded control characters (%00-%1f, %7f).
var encodedCtlRe = regexp.MustCompile(`(?i)%(?:[01][0-9a-f]|7f)`)

// probeHeaders are the only request headers a path probe may add. Anything
// else could override the method (X-HTTP-Method-Override), rewrite the URL
// (X-Original-URL), spoof the client (Forwarded) or carry credentials.
var probeHeaders = map[string]bool{
	"Accept":            true,
	"Accept-Language":   true,
	"X-Requested-With":  true,
	"If-None-Match":     true,
	"If-Modified-Since": true,
}

// PathResponse is the result of FetchPath. Headers are bounded and
// sanitised like HTTPObs.Headers; Body is capped at Options.MaxBody.
type PathResponse struct {
	Status  int
	Headers map[string][]string
	Body    []byte
}

// FetchPath performs one GET or HEAD of path on the endpoint itself: the
// endpoint's IP must be in scope, the request goes to that IP only and
// redirects are not followed. path must be an absolute path ("/x", query
// allowed) without scheme, host, fragment or traversal. hdr may add request
// headers but never credentials, Host or body framing. It shares the
// prober's rate limiter, retries and body cap.
func (p *HTTPProber) FetchPath(ctx context.Context, ep model.Endpoint, method, path string, hdr http.Header) (PathResponse, error) {
	if method != http.MethodGet && method != http.MethodHead {
		return PathResponse{}, ErrMethodNotAllowed
	}
	if err := CheckProbePath(path); err != nil {
		return PathResponse{}, err
	}
	if err := CheckProbeHeaders(hdr); err != nil {
		return PathResponse{}, err
	}
	if !ep.Key.IP.IsValid() {
		return PathResponse{}, errors.New("httpfp: endpoint without IP")
	}
	if ep.Scheme != "" && ep.Scheme != "http" && ep.Scheme != "https" {
		return PathResponse{}, fmt.Errorf("httpfp: unsupported scheme %q", ep.Scheme)
	}
	ip := ep.Key.IP.Unmap()
	if err := p.check(ip); err != nil {
		return PathResponse{}, err
	}
	base, err := url.Parse(BaseURL(ep))
	if err != nil {
		return PathResponse{}, err
	}
	ref, err := url.Parse(path)
	if err != nil {
		return PathResponse{}, fmt.Errorf("%w: %v", ErrBadPath, err)
	}
	c := p.client(endpointTarget(ip.String(), ep.Key.VHost), nil)
	defer c.CloseIdleConnections()
	resp, err := p.fetchRetry(ctx, c, method, base.ResolveReference(ref).String(), p.opt.MaxBody, hdr)
	if err != nil {
		return PathResponse{}, fmt.Errorf("httpfp: %s %s: %w", method, path, err)
	}
	return PathResponse{Status: resp.status, Headers: cleanHeaders(resp.header), Body: resp.body}, nil
}

// CheckProbePath accepts only a plain absolute path on the same host: no
// scheme, host, fragment, traversal (literal or encoded), double encoding
// or control characters (literal or encoded). Errors wrap ErrBadPath.
func CheckProbePath(p string) error {
	lower := strings.ToLower(p)
	switch {
	case p == "" || len(p) > maxProbePath:
		return fmt.Errorf("%w: empty or longer than %d bytes", ErrBadPath, maxProbePath)
	case !strings.HasPrefix(p, "/") || strings.HasPrefix(p, "//"):
		return fmt.Errorf("%w: must start with a single /", ErrBadPath)
	case strings.ContainsAny(p, " #\\") || strings.ContainsFunc(p, isCtl) ||
		encodedCtlRe.MatchString(p) || strings.Contains(p, "%25"):
		return fmt.Errorf("%w: forbidden character", ErrBadPath)
	case strings.Contains(p, "..") || strings.Contains(lower, "%2e") ||
		strings.Contains(lower, "%2f") || strings.Contains(lower, "%5c"):
		return fmt.Errorf("%w: traversal", ErrBadPath)
	case strings.Contains(p, "://"):
		return fmt.Errorf("%w: contains a URL", ErrBadPath)
	}
	u, err := url.Parse(p)
	if err != nil || u.Scheme != "" || u.Host != "" || u.Opaque != "" {
		return fmt.Errorf("%w: not a plain path", ErrBadPath)
	}
	return nil
}

func isCtl(r rune) bool { return r < 0x20 || r == 0x7f }

// CheckProbeHeaders accepts only the allowlisted request headers, with
// short single-line values. Errors wrap ErrBadHeader.
func CheckProbeHeaders(h http.Header) error {
	if len(h) > maxProbeHeaders {
		return fmt.Errorf("%w: more than %d headers", ErrBadHeader, maxProbeHeaders)
	}
	for k, vs := range h {
		if !probeHeaders[http.CanonicalHeaderKey(k)] {
			return fmt.Errorf("%w: %s", ErrBadHeader, k)
		}
		for _, v := range vs {
			if len(v) > maxProbeHdrVal || strings.ContainsFunc(v, isCtl) {
				return fmt.Errorf("%w: value of %s", ErrBadHeader, k)
			}
		}
	}
	return nil
}
