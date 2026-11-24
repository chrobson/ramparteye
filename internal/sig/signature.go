// Package sig loads, validates and evaluates safe YAML detection signatures.
//
// A signature only reads what the scanner already observed (nmap service
// fields, the HTTP fingerprint) plus at most MaxPaths extra GET/HEAD
// requests to the service itself. The validator rejects every other method,
// request bodies, credential headers and paths that could leave the host.
package sig

import (
	"regexp"
	"strings"

	"github.com/chrobson/ramparteye/internal/model"
)

// Signature sources.
const (
	SourceBuiltin = "builtin" // embedded in the binary (internal/sig/builtin)
	SourceCustom  = "custom"  // written by a user
	SourceNuclei  = "nuclei"  // converted from a nuclei template
)

// Sources lists every valid Signature.Source.
var Sources = []string{SourceBuiltin, SourceCustom, SourceNuclei}

// Severities accepted in Signature.Severity and Outdated.Severity
// (DefectDojo levels, written in lower case in YAML).
var Severities = []string{"info", "low", "medium", "high", "critical"}

// Categories accepted in Signature.Category.
var Categories = []string{"cms", "framework", "server", "iot", "admin-panel", "staging", "other"}

// Matcher types.
const (
	TypeHeader   = "header"
	TypeCookie   = "cookie"
	TypeTitle    = "title"
	TypeBody     = "body"
	TypeFavicon  = "favicon"
	TypeStatus   = "status"
	TypePath     = "path"
	TypeTLS      = "tls"
	TypeHostname = "hostname"
	TypeService  = "service"
)

// MatcherTypes lists every supported matcher type.
var MatcherTypes = []string{TypeHeader, TypeCookie, TypeTitle, TypeBody, TypeFavicon, TypeStatus, TypePath, TypeTLS, TypeHostname, TypeService}

// Signature is one detection rule loaded from YAML.
type Signature struct {
	ID          string `yaml:"id"`
	Name        string `yaml:"name"`
	Category    string `yaml:"category"`
	Confidence  int    `yaml:"confidence"`
	Description string `yaml:"description,omitempty"`
	Condition   string `yaml:"condition,omitempty"` // or (default) | and
	// Severity overrides the category default in exports (info|low|medium|
	// high|critical), e.g. high for an unauthenticated management API.
	Severity string `yaml:"severity,omitempty"`
	// Outdated raises the severity when the detected version (a named
	// "version" regex group) is older than Below. With "or", matching goes
	// on after the first hit until some matcher yields a version.
	Outdated *OutdatedRule `yaml:"outdated,omitempty"`
	// Optional classification, passed to the UI and to DefectDojo
	// (cwe -> cwe, remediation -> mitigation, references -> references).
	CWE         []int         `yaml:"cwe,omitempty"`         // CWE ids, most specific first
	Attack      []string      `yaml:"attack,omitempty"`      // MITRE ATT&CK technique ids (T1190, T1078.001)
	Remediation string        `yaml:"remediation,omitempty"` // one or two sentences
	References  []string      `yaml:"references,omitempty"`  // http(s) URLs
	Matchers    []MatcherSpec `yaml:"matchers"`

	// Raw is the source YAML (stored in the signatures table).
	Raw string `yaml:"-"`
	// Source is where the signature comes from (SourceBuiltin, SourceCustom
	// or SourceNuclei). It is not part of the YAML.
	Source string `yaml:"-"`
	// Enabled is false for a signature switched off by a user, or imported
	// for review (nuclei).
	Enabled bool `yaml:"-"`
	// PathProbe is true when the signature sends extra requests (path
	// matchers); those count against the per-host path probe budget.
	PathProbe bool `yaml:"-"`
}

// OutdatedRule flags versions older than Below (dotted numbers, e.g. "6.0").
type OutdatedRule struct {
	Below    string `yaml:"below"`
	Severity string `yaml:"severity"`
}

// MatcherSpec is one matcher. Which fields apply depends on Type.
type MatcherSpec struct {
	Type string `yaml:"type"`
	// Negate inverts a service, header, title or body matcher (e.g. "the
	// nmap extra info does not mention authentication"); its evidence key is
	// "not:<type>". A negated HTTP matcher never matches a service without
	// an HTTP response.
	Negate bool `yaml:"negate,omitempty"`
	// VersionOnly marks a matcher that never establishes a match by itself:
	// it runs only after the signature matched ("or"), to read a version
	// (e.g. a /readme.html probe sent to WordPress sites only).
	VersionOnly bool `yaml:"version_only,omitempty"`

	// header: Name + optional Regex (presence only if empty).
	// cookie: Name (exact, case-insensitive) or Regex over cookie names.
	Name  string `yaml:"name,omitempty"`
	Regex string `yaml:"regex,omitempty"` // title/body/header/cookie/hostname; path: response body

	// status / path: accepted status codes.
	Status []int `yaml:"status,omitempty"`

	// favicon: Shodan-compatible mmh3 hashes.
	Hashes []int32 `yaml:"hashes,omitempty"`

	// path probe: one extra GET/HEAD request.
	Path        string            `yaml:"path,omitempty"`
	Method      string            `yaml:"method,omitempty"`
	Headers     map[string]string `yaml:"headers,omitempty"` // request headers (no auth)
	Body        string            `yaml:"body,omitempty"`    // request body: always rejected
	Header      string            `yaml:"header,omitempty"`  // response header name to check
	HeaderRegex string            `yaml:"header_regex,omitempty"`

	// tls: flags that must all be true on the leaf certificate.
	Expired    bool `yaml:"expired,omitempty"`
	SelfSigned bool `yaml:"self_signed,omitempty"`
	Mismatch   bool `yaml:"hostname_mismatch,omitempty"`

	// service: nmap fields (no HTTP needed).
	Product string `yaml:"product,omitempty"` // regex over product + version
	Banner  string `yaml:"banner,omitempty"`  // regex over banner + extrainfo
	Ports   []int  `yaml:"ports,omitempty"`

	// Compiled by Validate.
	re       *regexp.Regexp
	hdrRe    *regexp.Regexp
	prodRe   *regexp.Regexp
	bannerRe *regexp.Regexp
}

// Meta returns the signature's classification (nil when it has none).
func (s *Signature) Meta() *model.SignatureMeta {
	m := &model.SignatureMeta{
		CWE:         append([]int(nil), s.CWE...),
		Attack:      append([]string(nil), s.Attack...),
		Remediation: strings.Join(strings.Fields(s.Remediation), " "),
		References:  append([]string(nil), s.References...),
	}
	if m.Empty() {
		return nil
	}
	return m
}

// hasPathMatcher reports whether the signature sends extra requests.
func (s *Signature) hasPathMatcher() bool {
	for i := range s.Matchers {
		if s.Matchers[i].Type == TypePath {
			return true
		}
	}
	return false
}

// hasVersionGroup reports whether a matcher's regex captures a version.
func (m *MatcherSpec) hasVersionGroup() bool {
	for _, re := range []*regexp.Regexp{m.re, m.prodRe, m.bannerRe} {
		if re != nil && re.SubexpIndex("version") > 0 {
			return true
		}
	}
	return false
}

// DojoSeverity maps a YAML severity to the DefectDojo spelling ("high" -> "High").
func DojoSeverity(s string) string {
	if s == "" {
		return ""
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
