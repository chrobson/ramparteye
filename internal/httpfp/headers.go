package httpfp

import (
	"net/http"
	"sort"
	"strings"
)

const redacted = "[redacted]"

// IsSensitiveHeader reports header names that can carry credentials.
func IsSensitiveHeader(name string) bool {
	n := strings.ToLower(name)
	switch n {
	case "authorization", "proxy-authorization", "cookie":
		return true
	}
	return strings.Contains(n, "auth") || strings.Contains(n, "token") ||
		strings.Contains(n, "api-key") || strings.Contains(n, "apikey") ||
		strings.Contains(n, "secret") || strings.Contains(n, "session") ||
		strings.Contains(n, "password")
}

// cleanHeaders copies response headers into a bounded, sanitised map. It
// drops Set-Cookie (cookies are recorded separately, without values) and
// replaces the values of sensitive headers with a marker. The challenge
// headers WWW-Authenticate and Proxy-Authenticate are public fingerprint
// data (scheme, realm) and are kept.
func cleanHeaders(h http.Header) map[string][]string {
	keys := make([]string, 0, len(h))
	for k := range h {
		if !strings.EqualFold(k, "Set-Cookie") {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	if len(keys) > maxHeaders {
		keys = keys[:maxHeaders]
	}
	out := make(map[string][]string, len(keys))
	for _, k := range keys {
		vs := h[k]
		if len(vs) > maxHeaderValues {
			vs = vs[:maxHeaderValues]
		}
		name := clean(k, maxHeaderName)
		vals := make([]string, 0, len(vs))
		for _, v := range vs {
			switch {
			case isChallenge(k) || !IsSensitiveHeader(k):
				vals = append(vals, clean(v, maxHeaderValue))
			default:
				vals = append(vals, redacted)
			}
		}
		out[name] = vals
	}
	return out
}

func isChallenge(name string) bool {
	return strings.EqualFold(name, "WWW-Authenticate") ||
		strings.EqualFold(name, "Proxy-Authenticate")
}
