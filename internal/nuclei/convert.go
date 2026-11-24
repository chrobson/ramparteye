// Package nuclei converts the passive subset of nuclei HTTP templates into
// RampartEye signatures. Everything that could send a request body, use a
// method other than GET/HEAD, expand variables, reach another host or need
// the nuclei DSL is rejected with a reason; converted signatures are always
// imported disabled, for review. The package is pure: no network, no store.
package nuclei

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"go.yaml.in/yaml/v3"

	"github.com/chrobson/ramparteye/internal/sig"
)

// Limits on imported templates.
const (
	MaxTemplateBytes = 256 << 10 // larger templates are rejected unread
	maxYAMLDepth     = 32
	maxYAMLNodes     = 20000
	maxFieldLen      = 1024
	maxCWE           = 5
	maxReferences    = 8
	// importConfidence is the confidence given to imported signatures.
	importConfidence = 60
)

// RejectError says why a template cannot be imported.
type RejectError struct{ Reason string }

func (e *RejectError) Error() string { return "nuclei template rejected: " + e.Reason }

func reject(format string, a ...any) error {
	return &RejectError{Reason: fmt.Sprintf(format, a...)}
}

// protocols are the non-HTTP nuclei protocols, all rejected.
var protocols = []string{"headless", "network", "tcp", "dns", "code", "file", "ssl", "websocket", "whois", "javascript", "workflows"}

// ignoredRequestFields do not change what is sent or matched passively.
var ignoredRequestFields = map[string]bool{
	"id": true, "name": true, "stop-at-first-match": true, "redirects": true, "host-redirects": true,
	"max-redirects": true, "extractors": true, "max-size": true, "cookie-reuse": true,
	"disable-path-automerge": true, "skip-variables-check": true,
}

var (
	idCleanRe = regexp.MustCompile(`[^a-z0-9_-]+`)
	cweRe     = regexp.MustCompile(`(?i)^cwe-(\d{1,4})$`)
	// headerWordRe splits "Name: value" (optionally behind (?i) and ^).
	headerWordRe  = regexp.MustCompile(`^((?:\(\?[a-z]+\))?)\^?([A-Za-z0-9-]+):(?s:(.*))$`)
	leadingSpaceR = regexp.MustCompile(`^(?:\\s\*|\\s\+|\\s|\s)+`)
)

type info struct {
	Name           string    `yaml:"name"`
	Severity       string    `yaml:"severity"`
	Description    string    `yaml:"description"`
	Remediation    string    `yaml:"remediation"`
	Reference      yaml.Node `yaml:"reference"`
	Classification struct {
		CWEID yaml.Node `yaml:"cwe-id"`
	} `yaml:"classification"`
}

type nucleiMatcher struct {
	Type            string   `yaml:"type"`
	Part            string   `yaml:"part"`
	Words           []string `yaml:"words"`
	Regex           []string `yaml:"regex"`
	Status          []int    `yaml:"status"`
	Condition       string   `yaml:"condition"`
	Negative        bool     `yaml:"negative"`
	CaseInsensitive bool     `yaml:"case-insensitive"`
	Encoding        string   `yaml:"encoding"`
}

// Convert turns one nuclei template into a disabled nuclei-sourced
// signature, or returns a *RejectError. The result passes sig.Validate and
// Raw holds the YAML that re-parses to the same signature.
func Convert(b []byte) (*sig.Signature, error) {
	if len(b) > MaxTemplateBytes {
		return nil, reject("template too large: %d bytes (max %d)", len(b), MaxTemplateBytes)
	}
	if bytes.Contains(bytes.ToLower(b), []byte("interactsh")) {
		return nil, reject("interactsh (out-of-band) templates not allowed")
	}
	var root yaml.Node
	if err := yaml.NewDecoder(bytes.NewReader(b)).Decode(&root); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, reject("empty template")
		}
		return nil, reject("invalid yaml: %v", err)
	}
	nodes := 0
	if msg := checkNode(&root, 0, &nodes); msg != "" {
		return nil, reject("%s", msg)
	}
	if len(root.Content) == 0 || root.Content[0].Kind != yaml.MappingNode {
		return nil, reject("template must be a yaml mapping")
	}
	top := map[string]*yaml.Node{}
	for i := 0; i+1 < len(root.Content[0].Content); i += 2 {
		top[root.Content[0].Content[i].Value] = root.Content[0].Content[i+1]
	}
	for _, p := range protocols {
		if _, ok := top[p]; ok {
			return nil, reject("protocol %s not supported (HTTP only)", p)
		}
	}
	for k := range top {
		if k != "id" && k != "info" && k != "http" && k != "requests" {
			return nil, reject("field %q not supported", k)
		}
	}
	var id string
	if n := top["id"]; n != nil {
		_ = n.Decode(&id)
	}
	if strings.TrimSpace(id) == "" {
		return nil, reject("template id is required")
	}
	var inf info
	if n := top["info"]; n != nil {
		if err := n.Decode(&inf); err != nil {
			return nil, reject("invalid info: %v", err)
		}
	}
	reqNode, err := singleRequest(top)
	if err != nil {
		return nil, err
	}
	s := &sig.Signature{
		ID:          "nuclei-" + cleanID(id),
		Name:        truncate(strings.TrimSpace(inf.Name), 128),
		Category:    "other",
		Confidence:  importConfidence,
		Description: truncate(strings.TrimSpace(inf.Description), maxFieldLen),
		Severity:    mapSeverity(inf.Severity),
		CWE:         parseCWE(&inf.Classification.CWEID),
		Remediation: truncate(strings.TrimSpace(inf.Remediation), maxFieldLen),
		References:  parseReferences(&inf.Reference),
	}
	if s.Name == "" {
		s.Name = strings.TrimSpace(id)
	}
	if err := convertRequest(reqNode, s); err != nil {
		return nil, err
	}
	raw, err := yaml.Marshal(s)
	if err != nil {
		return nil, reject("cannot encode signature: %v", err)
	}
	parsed, err := sig.Parse(raw)
	if err != nil {
		return nil, reject("%s", validateReason(err))
	}
	parsed.Source = sig.SourceNuclei
	parsed.Enabled = false
	return parsed, nil
}

// validateReason flattens sig's validation problems into one line.
func validateReason(err error) string {
	var ve *sig.ValidationError
	if errors.As(err, &ve) {
		msgs := make([]string, len(ve.Problems))
		for i, p := range ve.Problems {
			msgs[i] = p.Error()
		}
		return strings.Join(msgs, "; ")
	}
	return err.Error()
}

// checkNode refuses anchors, aliases and oversized or too deep documents.
func checkNode(n *yaml.Node, depth int, count *int) string {
	*count++
	switch {
	case n.Kind == yaml.AliasNode || n.Anchor != "":
		return "yaml anchors and aliases not allowed"
	case depth > maxYAMLDepth:
		return "yaml nested too deeply"
	case *count > maxYAMLNodes:
		return "yaml has too many nodes"
	}
	for _, c := range n.Content {
		if msg := checkNode(c, depth+1, count); msg != "" {
			return msg
		}
	}
	return ""
}

// singleRequest returns the one HTTP request of the template.
func singleRequest(top map[string]*yaml.Node) (*yaml.Node, error) {
	var reqs []*yaml.Node
	for _, k := range []string{"http", "requests"} {
		if n := top[k]; n != nil {
			if n.Kind != yaml.SequenceNode {
				return nil, reject("%s must be a list of requests", k)
			}
			reqs = append(reqs, n.Content...)
		}
	}
	switch {
	case len(reqs) == 0:
		return nil, reject("no http request")
	case len(reqs) > 1:
		return nil, reject("more than one request not allowed")
	case reqs[0].Kind != yaml.MappingNode:
		return nil, reject("request must be a mapping")
	}
	return reqs[0], nil
}

// convertRequest converts the request's matchers into s.Matchers.
func convertRequest(n *yaml.Node, s *sig.Signature) error {
	fields := map[string]*yaml.Node{}
	keys := []string{}
	for i := 0; i+1 < len(n.Content); i += 2 {
		k := n.Content[i].Value
		fields[k] = n.Content[i+1]
		keys = append(keys, k)
	}
	sort.Strings(keys)
	// Specific reasons first, then the allowlist.
	switch {
	case fields["raw"] != nil:
		return reject("raw requests not allowed")
	case fields["body"] != nil:
		return reject("request body not allowed")
	case fields["payloads"] != nil:
		return reject("payloads not allowed")
	case fields["fuzzing"] != nil:
		return reject("fuzzing not allowed")
	}
	method := "GET"
	if m := fields["method"]; m != nil {
		method = strings.ToUpper(strings.TrimSpace(m.Value))
	}
	if method != "GET" && method != "HEAD" {
		return reject("method %s not allowed", method)
	}
	for _, k := range keys {
		switch k {
		case "method", "path", "headers", "matchers", "matchers-condition":
		default:
			if !ignoredRequestFields[k] {
				return reject("request field %q not supported", k)
			}
		}
	}

	paths := scalars(fields["path"])
	switch {
	case len(paths) == 0:
		return reject("request path is required")
	case len(paths) > 1:
		return reject("more than one request path not allowed")
	}
	probePath, probe, err := requestPath(paths[0])
	if err != nil {
		return err
	}

	var headers map[string]string
	if h := fields["headers"]; h != nil {
		if err := h.Decode(&headers); err != nil {
			return reject("headers must be a string mapping")
		}
		for k, v := range headers {
			if strings.Contains(k, "{{") || strings.Contains(v, "{{") {
				return reject("template variable in request header %q not supported", k)
			}
		}
		if len(headers) > 0 && !probe {
			return reject("request headers need a path other than {{BaseURL}}")
		}
	}
	if method == "HEAD" && !probe {
		return reject("method HEAD needs a path other than {{BaseURL}}")
	}

	cond := "or"
	if c := fields["matchers-condition"]; c != nil {
		switch strings.ToLower(strings.TrimSpace(c.Value)) {
		case "or":
		case "and":
			cond = "and"
		default:
			return reject("matchers-condition %q not supported", c.Value)
		}
	}
	var ms []nucleiMatcher
	if mn := fields["matchers"]; mn != nil {
		if err := mn.Decode(&ms); err != nil {
			return reject("invalid matchers: %v", err)
		}
	}
	if len(ms) == 0 {
		return reject("at least one matcher is required")
	}

	b := &builder{probe: probe, path: probePath, method: method, headers: headers}
	needAnd := false
	for i := range ms {
		out, and, err := b.matcher(&ms[i])
		if err != nil {
			return err
		}
		needAnd = needAnd || and
		s.Matchers = append(s.Matchers, out...)
	}
	if needAnd && cond == "or" && len(ms) > 1 {
		return reject("word/regex condition and with matchers-condition or not supported")
	}
	s.Condition = cond
	if needAnd {
		s.Condition = "and"
	}
	return nil
}

// requestPath turns "{{BaseURL}}/x" into "/x"; probe is false for the base page.
func requestPath(p string) (string, bool, error) {
	rest := ""
	switch {
	case strings.HasPrefix(p, "{{BaseURL}}"):
		rest = p[len("{{BaseURL}}"):]
	case strings.HasPrefix(p, "{{RootURL}}"):
		rest = p[len("{{RootURL}}"):]
	default:
		if i := strings.Index(p, "{{"); i >= 0 {
			return "", false, reject("template expression %q not supported in path", p[i:])
		}
		return "", false, reject("path %q must start with {{BaseURL}} or {{RootURL}}", p)
	}
	if i := strings.Index(rest, "{{"); i >= 0 {
		expr := rest[i:]
		if end := strings.Index(expr, "}}"); end >= 0 {
			expr = expr[:end+2]
		}
		return "", false, reject("template expression %q not supported in path", expr)
	}
	if strings.HasPrefix(rest, "?") {
		rest = "/" + rest
	}
	if rest == "" || rest == "/" {
		return "/", false, nil
	}
	return rest, true, nil
}

// builder turns nuclei matchers into signature matchers for one request.
type builder struct {
	probe   bool
	path    string
	method  string
	headers map[string]string
}

// matcher converts one nuclei matcher. and reports that the result needs
// signature condition "and" (a words/regex "and" expanded into several).
func (b *builder) matcher(m *nucleiMatcher) (out []sig.MatcherSpec, and bool, err error) {
	if m.Encoding != "" {
		return nil, false, reject("matcher encoding not supported")
	}
	if m.Negative && b.probe {
		return nil, false, reject("negative matchers not supported on path probes")
	}
	switch m.Type {
	case "status":
		if m.Negative {
			return nil, false, reject("negative status matcher not supported")
		}
		if len(m.Status) == 0 {
			return nil, false, reject("status matcher without status codes")
		}
		spec := sig.MatcherSpec{Type: sig.TypeStatus, Status: m.Status}
		if b.probe {
			spec = b.pathSpec()
			spec.Status = m.Status
		}
		return []sig.MatcherSpec{spec}, false, nil
	case "word", "regex":
	default:
		return nil, false, reject("matcher type %s not supported", m.Type)
	}

	patterns := make([]string, 0, len(m.Words)+len(m.Regex))
	if m.Type == "word" {
		for _, w := range m.Words {
			patterns = append(patterns, regexp.QuoteMeta(w))
		}
	} else {
		patterns = append(patterns, m.Regex...)
	}
	if len(patterns) == 0 {
		return nil, false, reject("%s matcher without patterns", m.Type)
	}
	for _, p := range patterns {
		if strings.Contains(p, "{{") {
			return nil, false, reject("template variable in %s matcher not supported", m.Type)
		}
	}
	if m.CaseInsensitive {
		for i := range patterns {
			patterns[i] = "(?i)" + patterns[i]
		}
	}
	switch strings.ToLower(m.Part) {
	case "", "body", "header":
	default:
		return nil, false, reject("matcher part %q not supported (body or header)", m.Part)
	}
	header := strings.ToLower(m.Part) == "header"
	switch strings.ToLower(strings.TrimSpace(m.Condition)) {
	case "", "or":
	case "and":
		and = len(patterns) > 1
	default:
		return nil, false, reject("matcher condition %q not supported", m.Condition)
	}
	if and && m.Negative {
		return nil, false, reject("negative matcher with condition and not supported")
	}
	groups := [][]string{patterns}
	if and {
		groups = groups[:0]
		for _, p := range patterns {
			groups = append(groups, []string{p})
		}
	}
	for _, g := range groups {
		spec, err := b.single(g, header, m.Negative)
		if err != nil {
			return nil, false, err
		}
		out = append(out, spec)
	}
	return out, and, nil
}

// single builds one matcher from alternative patterns.
func (b *builder) single(patterns []string, header, negative bool) (sig.MatcherSpec, error) {
	if !header {
		spec := sig.MatcherSpec{Type: sig.TypeBody, Regex: alternate(patterns), Negate: negative}
		if b.probe {
			spec = b.pathSpec()
			spec.Regex = alternate(patterns)
		}
		return spec, nil
	}
	name := ""
	values := make([]string, 0, len(patterns))
	presence := false
	for _, p := range patterns {
		flags, n, rest, ok := splitHeaderPattern(p)
		if !ok {
			return sig.MatcherSpec{}, reject("header pattern %q must start with a literal header name (Name: value)", p)
		}
		if name != "" && !strings.EqualFold(name, n) {
			return sig.MatcherSpec{}, reject("header patterns must share one header name")
		}
		name = n
		if rest == "" {
			presence = true // a bare "Name:" word only asks for the header
		}
		values = append(values, flags+rest)
	}
	re := ""
	if !presence {
		re = alternate(values)
	}
	if b.probe {
		spec := b.pathSpec()
		spec.Header, spec.HeaderRegex = name, re
		return spec, nil
	}
	return sig.MatcherSpec{Type: sig.TypeHeader, Name: name, Regex: re, Negate: negative}, nil
}

func (b *builder) pathSpec() sig.MatcherSpec {
	spec := sig.MatcherSpec{Type: sig.TypePath, Path: b.path, Method: b.method}
	if len(b.headers) > 0 {
		spec.Headers = make(map[string]string, len(b.headers))
		for k, v := range b.headers {
			spec.Headers[k] = v
		}
	}
	return spec
}

// splitHeaderPattern splits "(?i)^Name:\s*value" into flags, name, value.
func splitHeaderPattern(p string) (flags, name, value string, ok bool) {
	m := headerWordRe.FindStringSubmatch(p)
	if m == nil {
		return "", "", "", false
	}
	value = strings.TrimSpace(leadingSpaceR.ReplaceAllString(m[3], ""))
	return m[1], m[2], value, true
}

// alternate joins patterns into one regex matching any of them.
func alternate(p []string) string {
	if len(p) == 1 {
		return p[0]
	}
	parts := make([]string, len(p))
	for i, s := range p {
		parts[i] = "(?:" + s + ")"
	}
	return strings.Join(parts, "|")
}

// scalars returns a scalar or list node as strings.
func scalars(n *yaml.Node) []string {
	if n == nil {
		return nil
	}
	if n.Kind == yaml.ScalarNode {
		return []string{n.Value}
	}
	var out []string
	_ = n.Decode(&out)
	return out
}

func mapSeverity(s string) string {
	switch v := strings.ToLower(strings.TrimSpace(s)); v {
	case "critical", "high", "medium", "low", "info":
		return v
	}
	return "info"
}

// parseCWE reads cwe-id given as "CWE-79", a list or "CWE-79, CWE-89".
func parseCWE(n *yaml.Node) []int {
	var out []int
	for _, s := range scalars(n) {
		for _, part := range strings.Split(s, ",") {
			if m := cweRe.FindStringSubmatch(strings.TrimSpace(part)); m != nil {
				if v, _ := strconv.Atoi(m[1]); v >= 1 && len(out) < maxCWE {
					out = append(out, v)
				}
			}
		}
	}
	return out
}

// parseReferences keeps the http(s) references and drops the rest.
func parseReferences(n *yaml.Node) []string {
	var out []string
	for _, r := range scalars(n) {
		r = strings.TrimSpace(r)
		if (strings.HasPrefix(r, "http://") || strings.HasPrefix(r, "https://")) &&
			len(r) <= 512 && !strings.ContainsAny(r, " \t\r\n") && len(out) < maxReferences {
			out = append(out, r)
		}
	}
	return out
}

// cleanID lower-cases id and replaces characters sig does not allow.
func cleanID(id string) string {
	id = idCleanRe.ReplaceAllString(strings.ToLower(strings.TrimSpace(id)), "-")
	id = strings.Trim(id, "-_")
	if limit := 64 - len("nuclei-"); len(id) > limit {
		id = id[:limit]
	}
	return id
}

// truncate cuts s to at most n bytes on a rune boundary.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	s = s[:n]
	for !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s
}
