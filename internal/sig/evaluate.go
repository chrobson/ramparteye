package sig

import (
	"context"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/chrobson/ramparteye/internal/model"
)

// maxEvidence caps one evidence value in bytes.
const maxEvidence = 200

// maxRegexInput caps the body bytes a regex reads (the start of the page
// carries the fingerprints; this bounds the cost of every body match).
const maxRegexInput = 64 << 10

// regexInput returns the part of a body regexes are run on.
func regexInput(b []byte) string {
	if len(b) > maxRegexInput {
		b = b[:maxRegexInput]
	}
	return string(b)
}

// evaluator evaluates signatures against one service observation.
type evaluator struct {
	ctx     context.Context
	svc     model.ServiceObs
	obs     model.HTTPObs
	fetcher Fetcher
	gate    func(netip.Addr) bool
	cache   map[string]*ProbeResponse // nil value = probe failed or refused
	version string                    // set by findRe on a "version" group
}

func newEvaluator(ctx context.Context, svc model.ServiceObs, obs model.HTTPObs, f Fetcher, gate func(netip.Addr) bool) *evaluator {
	return &evaluator{ctx: ctx, svc: svc, obs: obs, fetcher: f, gate: gate, cache: map[string]*ProbeResponse{}}
}

func (ev *evaluator) hasHTTP() bool { return ev.obs.Status != 0 }

// detect evaluates s and builds the detection when it matches.
func (ev *evaluator) detect(s *Signature) (model.Detection, bool) {
	evidence, ok := ev.signature(s)
	if !ok {
		return model.Detection{}, false
	}
	return model.Detection{
		ServiceID:   ev.svc.ID,
		SignatureID: s.ID,
		Name:        s.Name,
		Category:    s.Category,
		Confidence:  s.Confidence,
		Evidence:    evidence,
	}, true
}

// signature evaluates passive matchers first, then path probes, then
// version-only matchers, with short-circuiting so a failed "and" or a
// satisfied "or" sends no requests.
func (ev *evaluator) signature(s *Signature) (map[string]string, bool) {
	and := s.Condition == "and"
	evidence := map[string]string{}
	ordered := make([]*MatcherSpec, 0, len(s.Matchers))
	wantVersion := s.Outdated != nil
	for pass := 0; pass < 3; pass++ {
		for i := range s.Matchers {
			m := &s.Matchers[i]
			if m.VersionOnly {
				wantVersion = true
			}
			if (pass == 0 && !m.VersionOnly && m.Type != TypePath) ||
				(pass == 1 && !m.VersionOnly && m.Type == TypePath) ||
				(pass == 2 && m.VersionOnly) {
				ordered = append(ordered, m)
			}
		}
	}
	matched := false
	for _, m := range ordered {
		if m.VersionOnly && !matched {
			break // version-only matchers never establish a match
		}
		if matched && !and {
			// "or" is satisfied. A signature that wants a version keeps
			// looking for one, asking only matchers that can give it.
			if !wantVersion || evidence["version"] != "" {
				break
			}
			if !m.hasVersionGroup() {
				continue
			}
		}
		ev.version = ""
		key, val, ok := ev.matcher(m)
		if ok {
			if _, dup := evidence[key]; !dup {
				evidence[key] = clip(val)
			}
			if ev.version != "" && evidence["version"] == "" {
				evidence["version"] = clip(ev.version)
			}
			matched = true
		} else if and {
			return nil, false
		}
	}
	if !matched {
		return nil, false
	}
	applySeverity(s, evidence)
	return evidence, true
}

// applySeverity records the export severity of a detection in its evidence:
// the signature's severity, raised by the outdated rule when the detected
// version is older than outdated.below.
func applySeverity(s *Signature, evidence map[string]string) {
	if s.Severity != "" {
		evidence["severity"] = DojoSeverity(s.Severity)
	}
	o := s.Outdated
	if o == nil || evidence["version"] == "" {
		return
	}
	if c, ok := CompareVersions(evidence["version"], o.Below); ok && c < 0 {
		evidence["outdated"] = "version " + evidence["version"] + " < " + o.Below
		evidence["severity"] = DojoSeverity(o.Severity)
	}
}

// clip makes s valid UTF-8 and cuts it to maxEvidence bytes on a rune
// boundary.
func clip(s string) string {
	s = strings.ToValidUTF8(s, "")
	if len(s) <= maxEvidence {
		return s
	}
	cut := maxEvidence
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

func headerValues(h map[string][]string, name string) []string {
	if v, ok := h[http.CanonicalHeaderKey(name)]; ok {
		return v
	}
	for k, v := range h {
		if strings.EqualFold(k, name) {
			return v
		}
	}
	return nil
}

// findRe returns the full match of re in s. A named group "version", when
// it participated, is remembered and stored as evidence["version"].
func (ev *evaluator) findRe(re *regexp.Regexp, s string) (string, bool) {
	loc := re.FindStringSubmatchIndex(s)
	if loc == nil {
		return "", false
	}
	if i := re.SubexpIndex("version"); i > 0 && loc[2*i] >= 0 && loc[2*i+1] > loc[2*i] {
		ev.version = s[loc[2*i]:loc[2*i+1]]
	}
	return s[loc[0]:loc[1]], true
}

// matcher returns an evidence key/value when m matches (or, for a negated
// matcher, when it does not).
func (ev *evaluator) matcher(m *MatcherSpec) (string, string, bool) {
	if !m.Negate {
		return ev.positive(m)
	}
	if m.Type != TypeService && !ev.hasHTTP() {
		return "", "", false
	}
	_, _, ok := ev.positive(m)
	ev.version = ""
	if ok {
		return "", "", false
	}
	return "not:" + m.Type, "no match: " + m.describe(), true
}

// describe is the pattern of a matcher, for negated-match evidence.
func (m *MatcherSpec) describe() string {
	var parts []string
	if m.Name != "" {
		parts = append(parts, m.Name)
	}
	for _, p := range []string{m.Regex, m.Product, m.Banner} {
		if p != "" {
			parts = append(parts, p)
		}
	}
	return strings.Join(parts, " ")
}

// positive evaluates m without negation.
func (ev *evaluator) positive(m *MatcherSpec) (string, string, bool) {
	switch m.Type {
	case TypeService:
		return ev.service(m)
	case TypeHostname:
		for _, h := range ev.hostnames() {
			if _, ok := ev.findRe(m.re, h); ok {
				return "hostname", h, true
			}
		}
		return "", "", false
	}
	if !ev.hasHTTP() {
		return "", "", false
	}
	switch m.Type {
	case TypeHeader:
		vals := headerValues(ev.obs.Headers, m.Name)
		if vals == nil {
			return "", "", false
		}
		if m.re == nil {
			return "header:" + m.Name, strings.Join(vals, ", "), true
		}
		for _, v := range vals {
			if got, ok := ev.findRe(m.re, v); ok {
				return "header:" + m.Name, got, true
			}
		}
	case TypeCookie:
		for _, c := range ev.obs.Cookies {
			if m.Name != "" && strings.EqualFold(c.Name, m.Name) {
				return "cookie", c.Name, true
			}
			if m.re != nil && m.re.MatchString(c.Name) {
				return "cookie", c.Name, true
			}
		}
	case TypeTitle:
		if v, ok := ev.findRe(m.re, ev.obs.Title); ok {
			return "title", v, true
		}
	case TypeBody:
		if v, ok := ev.findRe(m.re, regexInput(ev.obs.Body)); ok {
			return "body", v, true
		}
	case TypeFavicon:
		if ev.obs.FaviconMMH3 != nil && slices.Contains(m.Hashes, *ev.obs.FaviconMMH3) {
			return "favicon_mmh3", strconv.Itoa(int(*ev.obs.FaviconMMH3)), true
		}
	case TypeStatus:
		if slices.Contains(m.Status, ev.obs.Status) {
			return "status", strconv.Itoa(ev.obs.Status), true
		}
	case TypeTLS:
		return ev.tls(m)
	case TypePath:
		return ev.path(m)
	}
	return "", "", false
}

func (ev *evaluator) tls(m *MatcherSpec) (string, string, bool) {
	t := ev.obs.TLS
	if t == nil {
		return "", "", false
	}
	if (m.Expired && !t.Expired) || (m.SelfSigned && !t.SelfSigned) || (m.Mismatch && !t.Mismatch) {
		return "", "", false
	}
	var flags []string
	if m.Expired {
		flags = append(flags, "expired "+t.NotAfter.UTC().Format(time.DateOnly))
	}
	if m.SelfSigned {
		flags = append(flags, "self-signed")
	}
	if m.Mismatch {
		flags = append(flags, "hostname mismatch")
	}
	return "tls", strings.Join(flags, ", ") + "; subject=" + t.Subject, true
}

func (ev *evaluator) service(m *MatcherSpec) (string, string, bool) {
	if len(m.Ports) > 0 && !slices.Contains(m.Ports, int(ev.svc.Key.Port)) {
		return "", "", false
	}
	val := "port " + strconv.Itoa(int(ev.svc.Key.Port))
	if m.prodRe != nil {
		s := strings.TrimSpace(ev.svc.Product + " " + ev.svc.Version)
		v, ok := ev.findRe(m.prodRe, s)
		if !ok || v == "" {
			return "", "", false
		}
		val = v
	}
	if m.bannerRe != nil {
		s := strings.TrimSpace(ev.svc.Banner + " " + ev.svc.ExtraInfo)
		v, ok := ev.findRe(m.bannerRe, s)
		if !ok || v == "" {
			return "", "", false
		}
		val = v
	}
	return "service", val, true
}

// hostnames lists names the service is known by: vhost, URL hosts in the
// redirect chain and certificate SANs / subject.
func (ev *evaluator) hostnames() []string {
	var out []string
	add := func(h string) {
		h = strings.ToLower(strings.TrimSpace(h))
		if h != "" && !slices.Contains(out, h) {
			out = append(out, h)
		}
	}
	add(ev.svc.Key.VHost)
	urls := []string{ev.obs.URL}
	for _, r := range ev.obs.Redirects {
		urls = append(urls, r.URL)
	}
	for _, raw := range urls {
		if u, err := url.Parse(raw); err == nil {
			add(u.Hostname())
		}
	}
	if ev.obs.TLS != nil {
		for _, s := range ev.obs.TLS.SANs {
			add(s)
		}
		if cn := commonName(ev.obs.TLS.Subject); cn != "" {
			add(cn)
		}
	}
	return out
}

func commonName(subject string) string {
	for _, part := range strings.Split(subject, ",") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(part), "CN="); ok {
			return v
		}
	}
	return ""
}

// probe returns the (cached) response to m's request, or nil when there is
// no fetcher, the context is done, the gate refuses or the request failed.
func (ev *evaluator) probe(m *MatcherSpec) *ProbeResponse {
	if ev.fetcher == nil {
		return nil
	}
	key := probeKey(m)
	if resp, cached := ev.cache[key]; cached {
		return resp
	}
	var resp *ProbeResponse
	if ev.ctx.Err() == nil && (ev.gate == nil || ev.gate(ev.svc.Key.IP.Unmap())) {
		r, err := ev.fetcher.Fetch(ev.ctx, ev.svc, ev.obs, ProbeRequest{Method: m.Method, Path: m.Path, Headers: m.Headers})
		if err == nil {
			resp = &r
		}
	}
	if ev.ctx.Err() == nil {
		ev.cache[key] = resp // a cancelled probe is not remembered as failed
	}
	return resp
}

// probeKey identifies a request: method, path and sorted headers.
func probeKey(m *MatcherSpec) string {
	key := m.Method + " " + m.Path
	names := make([]string, 0, len(m.Headers))
	for k := range m.Headers {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		key += "\n" + http.CanonicalHeaderKey(k) + ": " + m.Headers[k]
	}
	return key
}

func (ev *evaluator) path(m *MatcherSpec) (string, string, bool) {
	if ev.obs.URL == "" {
		return "", "", false
	}
	resp := ev.probe(m)
	if resp == nil {
		return "", "", false
	}
	if len(m.Status) > 0 && !slices.Contains(m.Status, resp.Status) {
		return "", "", false
	}
	val := m.Path + " -> " + strconv.Itoa(resp.Status)
	if m.Header != "" {
		vals := headerValues(resp.Header, m.Header)
		if vals == nil {
			return "", "", false
		}
		if m.hdrRe != nil {
			hit := false
			for _, v := range vals {
				if s := m.hdrRe.FindString(v); s != "" {
					val += " " + m.Header + ": " + s
					hit = true
					break
				}
			}
			if !hit {
				return "", "", false
			}
		}
	}
	if m.re != nil {
		v, ok := ev.findRe(m.re, regexInput(resp.Body))
		if !ok {
			return "", "", false
		}
		val += " body: " + v
	}
	return "path:" + m.Path, val, true
}
