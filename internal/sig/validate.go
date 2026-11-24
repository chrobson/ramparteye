package sig

import (
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"github.com/chrobson/ramparteye/internal/httpfp"
)

// Limits enforced by the validator.
const (
	MaxPaths     = 3  // distinct extra paths a signature may request
	MaxMatchers  = 12 // matchers per signature
	MaxYAMLBytes = 32 << 10
	maxPathLen   = 256
	maxHeaders   = 4
	maxRegexLen  = 1024

	maxCWE         = 5
	maxAttack      = 8
	maxReferences  = 8
	maxRemediation = 1024
	maxRefLen      = 512
)

var (
	attackRe     = regexp.MustCompile(`^T\d{4}(\.\d{3})?$`)
	idRe         = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{1,63}$`)
	headerNameRe = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)
)

// credentialParams are query parameter names that would turn a GET probe
// into a login or token attempt.
var credentialParams = []string{"pass", "pwd", "user", "login", "token", "secret", "auth", "key", "session", "cred"}

// ValidationError lists every problem found in a signature.
type ValidationError struct {
	ID       string
	Problems []error
}

func (e *ValidationError) Error() string {
	id := e.ID
	if id == "" {
		id = "?"
	}
	msgs := make([]string, len(e.Problems))
	for i, p := range e.Problems {
		msgs[i] = p.Error()
	}
	return fmt.Sprintf("signature %s: %s", id, strings.Join(msgs, "; "))
}

// Unwrap returns the individual problems.
func (e *ValidationError) Unwrap() []error { return e.Problems }

// Validate checks the safety rules and returns every problem found (nil
// when the signature is valid). As a side effect it compiles the regular
// expressions and defaults path probe methods to GET, so a signature must
// pass Validate before an Engine evaluates it.
func Validate(s *Signature) []error {
	var p []error
	add := func(f string, a ...any) { p = append(p, fmt.Errorf(f, a...)) }

	if !idRe.MatchString(s.ID) {
		add("id must match %s", idRe)
	}
	if strings.TrimSpace(s.Name) == "" || len(s.Name) > 128 {
		add("name is required (max 128 chars)")
	}
	if !slices.Contains(Categories, s.Category) {
		add("category must be one of %s", strings.Join(Categories, "|"))
	}
	if s.Confidence < 1 || s.Confidence > 100 {
		add("confidence must be 1-100")
	}
	switch s.Condition {
	case "", "or", "and":
	default:
		add("condition must be or|and")
	}
	if s.Severity != "" && !slices.Contains(Severities, s.Severity) {
		add("severity must be one of %s", strings.Join(Severities, "|"))
	}
	if s.Source != "" && !slices.Contains(Sources, s.Source) {
		add("source must be one of %s", strings.Join(Sources, "|"))
	}
	if o := s.Outdated; o != nil {
		if _, ok := parseVersion(o.Below); !ok {
			add("outdated.below must be a dotted version such as 6.0")
		}
		if !slices.Contains(Severities, o.Severity) {
			add("outdated.severity must be one of %s", strings.Join(Severities, "|"))
		}
	}
	p = append(p, validateMeta(s)...)
	if len(s.Matchers) == 0 {
		add("at least one matcher is required")
	}
	if len(s.Matchers) > MaxMatchers {
		add("too many matchers (max %d)", MaxMatchers)
	}
	paths := map[string]bool{}
	establishing := 0
	for i := range s.Matchers {
		m := &s.Matchers[i]
		pre := fmt.Sprintf("matcher %d (%s)", i+1, m.Type)
		for _, e := range validateMatcher(m) {
			add("%s: %s", pre, e)
		}
		if !m.VersionOnly {
			establishing++
		} else {
			if s.Condition == "and" {
				add("%s: version_only requires condition or", pre)
			}
			if m.Negate {
				add("%s: version_only cannot be negated", pre)
			}
			if !m.hasVersionGroup() {
				add("%s: version_only needs a regex with a named group (?P<version>...)", pre)
			}
		}
		if m.Type == TypePath {
			paths[m.Path] = true
		}
	}
	if len(s.Matchers) > 0 && establishing == 0 {
		add("at least one matcher must not be version_only")
	}
	if len(paths) > MaxPaths {
		add("too many extra paths: %d (max %d)", len(paths), MaxPaths)
	}
	return p
}

// validate returns Validate's problems as one error.
func validate(s *Signature) error {
	if p := Validate(s); len(p) > 0 {
		return &ValidationError{ID: s.ID, Problems: p}
	}
	return nil
}

// validateMeta checks cwe, attack, remediation and references.
func validateMeta(s *Signature) []error {
	var p []error
	add := func(f string, a ...any) { p = append(p, fmt.Errorf(f, a...)) }
	if len(s.CWE) > maxCWE {
		add("too many cwe ids (max %d)", maxCWE)
	}
	for _, c := range s.CWE {
		if c < 1 || c > 9999 {
			add("cwe %d must be a CWE number 1-9999 (write 306, not CWE-306)", c)
		}
	}
	if len(s.Attack) > maxAttack {
		add("too many attack ids (max %d)", maxAttack)
	}
	for _, a := range s.Attack {
		if !attackRe.MatchString(a) {
			add("attack %q must be a MITRE ATT&CK technique id such as T1190 or T1078.001", a)
		}
	}
	if len(s.Remediation) > maxRemediation {
		add("remediation too long (max %d chars)", maxRemediation)
	}
	if len(s.References) > maxReferences {
		add("too many references (max %d)", maxReferences)
	}
	for _, r := range s.References {
		u, err := url.Parse(r)
		switch {
		case len(r) > maxRefLen:
			add("reference too long (max %d chars)", maxRefLen)
		case err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || strings.ContainsAny(r, " \t\r\n"):
			add("reference %q must be an http:// or https:// URL", r)
		}
	}
	return p
}

func validateMatcher(m *MatcherSpec) []string {
	var p []string
	add := func(f string, a ...any) { p = append(p, fmt.Sprintf(f, a...)) }
	compile := func(field, expr string) *regexp.Regexp {
		if expr == "" {
			return nil
		}
		if len(expr) > maxRegexLen {
			add("%s regex too long", field)
			return nil
		}
		re, err := regexp.Compile(expr)
		if err != nil {
			add("%s regex: %v", field, err)
			return nil
		}
		return re
	}
	// Fields that only make sense on a path probe.
	if m.Type != TypePath {
		if m.Path != "" || m.Method != "" || len(m.Headers) > 0 || m.Header != "" || m.HeaderRegex != "" {
			add("path/method/headers/header only allowed on type path")
		}
	}
	if m.Body != "" {
		add("request body is not allowed")
	}
	switch m.Type {
	case TypeHeader:
		if !headerNameRe.MatchString(m.Name) {
			add("name must be a header name")
		}
		m.re = compile("regex", m.Regex)
	case TypeCookie:
		if m.Name == "" && m.Regex == "" {
			add("name or regex is required")
		}
		m.re = compile("regex", m.Regex)
	case TypeTitle, TypeBody, TypeHostname:
		if m.Regex == "" {
			add("regex is required")
		}
		m.re = compile("regex", m.Regex)
	case TypeFavicon:
		if len(m.Hashes) == 0 {
			add("hashes are required")
		}
	case TypeStatus:
		if len(m.Status) == 0 {
			add("status codes are required")
		}
		p = append(p, checkCodes(m.Status)...)
	case TypePath:
		p = append(p, validatePathMatcher(m)...)
		m.re = compile("regex", m.Regex)
		m.hdrRe = compile("header_regex", m.HeaderRegex)
	case TypeTLS:
		if !m.Expired && !m.SelfSigned && !m.Mismatch {
			add("set at least one of expired, self_signed, hostname_mismatch")
		}
	case TypeService:
		if m.Product == "" && m.Banner == "" && len(m.Ports) == 0 {
			add("product, banner or ports is required")
		}
		for _, port := range m.Ports {
			if port < 1 || port > 65535 {
				add("port %d out of range", port)
			}
		}
		m.prodRe = compile("product", m.Product)
		m.bannerRe = compile("banner", m.Banner)
	default:
		add("unknown matcher type (allowed: %s)", strings.Join(MatcherTypes, ", "))
	}
	if m.Type != TypeService && (m.Product != "" || m.Banner != "" || len(m.Ports) > 0) {
		add("product/banner/ports only allowed on type service")
	}
	if m.Type != TypeTLS && (m.Expired || m.SelfSigned || m.Mismatch) {
		add("expired/self_signed/hostname_mismatch only allowed on type tls")
	}
	if m.Negate {
		switch m.Type {
		case TypeService, TypeHeader, TypeTitle, TypeBody:
		default:
			add("negate only allowed on types service, header, title and body")
		}
	}
	if m.Type != TypeFavicon && len(m.Hashes) > 0 {
		add("hashes only allowed on type favicon")
	}
	if m.Type != TypeStatus && m.Type != TypePath && len(m.Status) > 0 {
		add("status only allowed on types status and path")
	}
	return p
}

// validatePathMatcher checks the request a path matcher would send.
func validatePathMatcher(m *MatcherSpec) []string {
	var p []string
	add := func(f string, a ...any) { p = append(p, fmt.Sprintf(f, a...)) }
	switch strings.ToUpper(m.Method) {
	case "", "GET", "HEAD":
		m.Method = strings.ToUpper(m.Method)
		if m.Method == "" {
			m.Method = "GET"
		}
	default:
		add("method %q not allowed (only GET or HEAD)", m.Method)
	}
	if err := checkPath(m.Path); err != "" {
		add("%s", err)
	}
	if len(m.Headers) > maxHeaders {
		add("too many request headers (max %d)", maxHeaders)
	}
	for k, v := range m.Headers {
		switch {
		case !headerNameRe.MatchString(k):
			add("invalid request header name %q", k)
		case httpfp.IsSensitiveHeader(k):
			add("auth/credential header %q is not allowed", k)
		case strings.EqualFold(k, "Host") || strings.EqualFold(k, "Content-Length") ||
			strings.EqualFold(k, "Transfer-Encoding") || strings.EqualFold(k, "Content-Type") ||
			strings.EqualFold(k, "User-Agent"):
			add("request header %q is not allowed", k)
		case strings.ContainsAny(v, "\r\n") || len(v) > 256:
			add("invalid value for request header %q", k)
		}
	}
	if len(m.Status) == 0 && m.Regex == "" && m.Header == "" {
		add("path probe needs status, regex or header to check")
	}
	p = append(p, checkCodes(m.Status)...)
	if m.Header != "" && !headerNameRe.MatchString(m.Header) {
		add("header must be a header name")
	}
	if m.HeaderRegex != "" && m.Header == "" {
		add("header_regex requires header")
	}
	return p
}

func checkCodes(codes []int) []string {
	var p []string
	for _, c := range codes {
		if c < 100 || c > 599 {
			p = append(p, fmt.Sprintf("status %d out of range", c))
		}
	}
	return p
}

func checkPath(p string) string {
	lower := strings.ToLower(p)
	switch {
	case p == "":
		return "path is required"
	case len(p) > maxPathLen:
		return "path too long"
	case !strings.HasPrefix(p, "/") || strings.HasPrefix(p, "//"):
		return "path must be absolute on the same host (start with a single /)"
	case strings.ContainsAny(p, "\r\n\t #\\") || strings.ContainsRune(p, 0):
		return "path contains forbidden characters"
	case strings.Contains(p, "..") || strings.Contains(lower, "%2e") || strings.Contains(lower, "%2f") || strings.Contains(lower, "%5c"):
		return "path must not contain .. or encoded traversal"
	case strings.Contains(p, "://"):
		return "path must not contain a URL"
	case credentialQuery(p):
		return "path query must not carry credentials (no login attempts)"
	}
	return ""
}

func credentialQuery(p string) bool {
	_, q, ok := strings.Cut(p, "?")
	if !ok {
		return false
	}
	vals, err := url.ParseQuery(q)
	if err != nil {
		return true
	}
	for name := range vals {
		n := strings.ToLower(name)
		for _, c := range credentialParams {
			if strings.Contains(n, c) {
				return true
			}
		}
	}
	return false
}
