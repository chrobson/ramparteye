package notify

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/chrobson/ramparteye/internal/urlcheck"
)

const (
	// DefaultAttemptTimeout bounds one HTTP attempt.
	DefaultAttemptTimeout = 10 * time.Second
	// maxAttempts is the number of HTTP attempts of one delivery.
	maxAttempts = 3
	// maxResponseBytes caps how much of a response is read (and discarded).
	maxResponseBytes = 4 << 10
	// maxErrorText bounds the error text of a delivery.
	maxErrorText = 300
	// defaultUserAgent is sent when Options.UserAgent is empty.
	defaultUserAgent = "ramparteye (+attack surface inventory)"
)

// Headers of a webhook request.
const (
	HeaderEvent     = "X-Rampart-Event"
	HeaderDelivery  = "X-Rampart-Delivery"
	HeaderTimestamp = "X-Rampart-Timestamp"
	HeaderSignature = "X-Rampart-Signature"
)

// defaultBackoff is the wait before the second and third attempt.
var defaultBackoff = []time.Duration{2 * time.Second, 8 * time.Second}

// newHTTPClient returns a verified-TLS client that never follows
// redirects. hc, when given, is copied with its redirect policy replaced.
func newHTTPClient(hc *http.Client) *http.Client {
	if hc == nil {
		tr := http.DefaultTransport.(*http.Transport).Clone()
		tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		hc = &http.Client{Transport: tr, Timeout: DefaultAttemptTimeout}
	}
	cp := *hc
	cp.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &cp
}

// result is the outcome of the HTTP part of a delivery.
type result struct {
	attempts int
	status   int // last HTTP status, 0 = no response
	err      error
}

// post sends body to t.url with up to maxAttempts attempts. Only network
// errors, 429 and 5xx are retried, after backoff[i]; a response outside
// 2xx is a failure (3xx included: redirects are never followed). The error
// is sanitised (see safeError).
func (n *Notifier) post(ctx context.Context, t target, event string, body []byte, now time.Time) result {
	id := make([]byte, 16)
	_, _ = rand.Read(id)
	h := http.Header{}
	h.Set("Content-Type", "application/json")
	h.Set("User-Agent", n.userAgent())
	h.Set(HeaderEvent, event)
	h.Set(HeaderDelivery, hex.EncodeToString(id))
	h.Set(HeaderTimestamp, strconv.FormatInt(now.Unix(), 10))
	if t.secret != "" {
		h.Set(HeaderSignature, Sign(t.secret, body))
	}
	backoff := n.opt.Backoff
	if backoff == nil {
		backoff = defaultBackoff
	}
	var res result
	for res.attempts < maxAttempts {
		if res.attempts > 0 {
			wait := time.Duration(0)
			if i := res.attempts - 1; i < len(backoff) {
				wait = backoff[i]
			}
			if !sleep(ctx, wait) {
				break
			}
		}
		res.attempts++
		status, err := n.attempt(ctx, t.url, h, body)
		res.status, res.err = status, err
		retry := (err != nil && ctx.Err() == nil) || status == http.StatusTooManyRequests || status >= 500
		if !retry {
			break
		}
	}
	if res.err == nil && (res.status < 200 || res.status > 299) {
		msg := "HTTP " + strconv.Itoa(res.status) + " " + http.StatusText(res.status)
		if res.status >= 300 && res.status < 400 {
			msg += " (redirects are not followed)"
		}
		res.err = errors.New(strings.TrimSpace(msg))
	}
	if res.err != nil {
		res.err = errors.New(safeError(res.err, t))
	}
	return res
}

// attempt sends one request and returns the response status; the response
// body is read up to maxResponseBytes and discarded.
func (n *Notifier) attempt(ctx context.Context, u *url.URL, h http.Header, body []byte) (int, error) {
	timeout := n.opt.AttemptTimeout
	if timeout <= 0 {
		timeout = DefaultAttemptTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header = h.Clone()
	resp, err := n.hc.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBytes))
	return resp.StatusCode, nil
}

// Sign returns the X-Rampart-Signature value of body:
// "sha256=" + hex(HMAC-SHA256(secret, body)).
func Sign(secret string, body []byte) string {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write(body)
	return "sha256=" + hex.EncodeToString(m.Sum(nil))
}

// sleep waits d unless ctx ends first; it reports whether it waited.
func sleep(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	tm := time.NewTimer(d)
	defer tm.Stop()
	select {
	case <-tm.C:
		return true
	case <-ctx.Done():
		return false
	}
}

// safeError turns a delivery error into history text that names at most
// the scheme and host of the webhook: the URL error wrapper (which holds
// the whole URL) is removed, timeouts and cancellations get fixed words,
// and any remaining trace of the path, query or secret is masked.
func safeError(err error, t target) string {
	var ue *url.Error
	if errors.As(err, &ue) {
		err = ue.Err
	}
	var ne net.Error
	var msg string
	switch {
	case errors.Is(err, context.Canceled):
		msg = "cancelled"
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, os.ErrDeadlineExceeded),
		errors.As(err, &ne) && ne.Timeout():
		msg = "timed out"
	default:
		msg = err.Error()
	}
	if t.url != nil {
		for _, s := range []string{t.url.String(), t.url.RawQuery, t.url.EscapedPath(), t.url.Path} {
			if len(s) > 1 {
				msg = strings.ReplaceAll(msg, s, "[redacted]")
			}
		}
	}
	if t.secret != "" {
		msg = strings.ReplaceAll(msg, t.secret, "[redacted]")
	}
	return clean(urlcheck.Origin(t.url)+": "+msg, maxErrorText)
}
