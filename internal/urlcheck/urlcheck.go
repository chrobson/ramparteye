// Package urlcheck validates the URLs of the endpoints an administrator
// configures (DefectDojo, webhooks, the public base URL). Such a URL may
// carry a credential in its path, query or userinfo, so errors are fixed
// phrases that never echo the input.
package urlcheck

import (
	"errors"
	"net/url"
	"strconv"
	"strings"
)

// Parse parses raw as an absolute http or https URL with a host, an optional
// valid port and no userinfo or fragment. A query is refused unless
// allowQuery. Surrounding space is trimmed; scheme and host are lowercased,
// the path is kept as given. The error is a phrase to be prefixed with what
// the URL is ("DefectDojo URL " + err.Error()).
func Parse(raw string, allowQuery bool) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	u, err := url.Parse(raw)
	if err != nil {
		return nil, errors.New("is not a valid URL")
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return nil, errors.New("must be an absolute http or https URL")
	}
	if u.Hostname() == "" {
		return nil, errors.New("needs a host")
	}
	if u.User != nil || strings.Contains(u.Host, "@") {
		return nil, errors.New("must not contain credentials")
	}
	fragment := u.Fragment != "" || strings.Contains(raw, "#")
	if !allowQuery && (fragment || u.RawQuery != "" || strings.Contains(raw, "?")) {
		return nil, errors.New("must not contain a query or fragment")
	}
	if fragment {
		return nil, errors.New("must not contain a fragment")
	}
	if strings.HasSuffix(u.Host, ":") {
		return nil, errors.New("has an empty port")
	}
	if p := u.Port(); p != "" {
		if n, err := strconv.Atoi(p); err != nil || n < 1 || n > 65535 {
			return nil, errors.New("has an invalid port")
		}
	}
	u.Scheme, u.Host = scheme, strings.ToLower(u.Host)
	return u, nil
}

// Origin returns scheme://host[:port] of u: the part of a configured URL
// that may be shown and logged ("" for nil).
func Origin(u *url.URL) string {
	if u == nil {
		return ""
	}
	return u.Scheme + "://" + u.Host
}
