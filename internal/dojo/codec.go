package dojo

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/chrobson/ramparteye/internal/model"
)

// ScanType is the DefectDojo parser name used for import-scan/reimport-scan.
const ScanType = "Generic Findings Import"

// dateLayout is the date format DefectDojo expects for "date".
const dateLayout = "2006-01-02"

// wireFile is the top-level Generic Findings document.
type wireFile struct {
	Findings []wireFinding `json:"findings"`
}

// wireFinding holds only keys accepted by DefectDojo's generic JSON parser
// (dojo/tools/generic/json_parser.py, release 3.5.202). Field order is the
// serialization order, so output is byte-for-byte deterministic.
type wireFinding struct {
	Title            string         `json:"title"`
	Severity         string         `json:"severity"`
	Description      string         `json:"description"`
	Observed         string         `json:"steps_to_reproduce,omitempty"`
	CWE              int            `json:"cwe,omitempty"`
	Mitigation       string         `json:"mitigation,omitempty"`
	References       string         `json:"references,omitempty"`
	Date             string         `json:"date,omitempty"`
	UniqueIDFromTool string         `json:"unique_id_from_tool,omitempty"`
	VulnIDFromTool   string         `json:"vuln_id_from_tool,omitempty"`
	Endpoints        []wireEndpoint `json:"endpoints,omitempty"`
	Tags             []string       `json:"tags,omitempty"`
}

// wireEndpoint uses a subset of the DefectDojo Endpoint model fields.
type wireEndpoint struct {
	Host     string `json:"host"`
	Port     int    `json:"port,omitempty"`
	Protocol string `json:"protocol,omitempty"`
	Path     string `json:"path,omitempty"`
}

// JSONCodec implements Codec for DefectDojo Generic Findings JSON.
type JSONCodec struct{}

// NewCodec returns the Generic Findings codec.
func NewCodec() Codec { return JSONCodec{} }

var _ Codec = JSONCodec{}

// Marshal encodes findings sorted by unique_id_from_tool (then title) and
// validates the result, so a file that DefectDojo would reject is never
// produced.
func (JSONCodec) Marshal(fs []model.Finding) ([]byte, error) {
	out := wireFile{Findings: make([]wireFinding, 0, len(fs))}
	for _, f := range fs {
		w := wireFinding{
			Title:            strings.TrimSpace(f.Title),
			Severity:         string(normalizeSeverity(string(f.Severity))),
			Description:      f.Description,
			Observed:         f.Observed,
			CWE:              f.CWE,
			Mitigation:       f.Mitigation,
			References:       f.References,
			UniqueIDFromTool: f.UniqueIDFromTool,
			VulnIDFromTool:   f.VulnIDFromTool,
		}
		if !f.Date.IsZero() {
			w.Date = f.Date.UTC().Format(dateLayout)
		}
		for _, k := range f.Endpoints {
			w.Endpoints = append(w.Endpoints, endpointFromKey(k))
		}
		if len(f.Tags) > 0 {
			w.Tags = normalizeTags(f.Tags)
		}
		out.Findings = append(out.Findings, w)
	}
	sort.SliceStable(out.Findings, func(i, j int) bool {
		a, b := out.Findings[i], out.Findings[j]
		if a.UniqueIDFromTool != b.UniqueIDFromTool {
			return a.UniqueIDFromTool < b.UniqueIDFromTool
		}
		return a.Title < b.Title
	})
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		return nil, err
	}
	b := buf.Bytes()
	if err := Validate(b); err != nil {
		return nil, fmt.Errorf("generated file is invalid: %w", err)
	}
	return b, nil
}

// lenientFinding accepts files produced by other tools: every key the
// DefectDojo generic parser allows is tolerated, unknown fields are ignored.
type lenientFinding struct {
	Title            string            `json:"title"`
	Severity         string            `json:"severity"`
	Description      string            `json:"description"`
	Observed         string            `json:"steps_to_reproduce"`
	CWE              json.RawMessage   `json:"cwe"`
	Mitigation       string            `json:"mitigation"`
	References       string            `json:"references"`
	Date             string            `json:"date"`
	UniqueIDFromTool string            `json:"unique_id_from_tool"`
	VulnIDFromTool   string            `json:"vuln_id_from_tool"`
	Endpoints        []json.RawMessage `json:"endpoints"`
	Tags             []string          `json:"tags"`
}

// Unmarshal parses a Generic Findings document. It is lenient about extra
// DefectDojo keys (use Validate for the strict RampartEye whitelist) but requires
// title, severity and description on every finding.
func (JSONCodec) Unmarshal(b []byte) ([]model.Finding, error) {
	var doc struct {
		Findings []lenientFinding `json:"findings"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("parse generic findings: %w", err)
	}
	out := make([]model.Finding, 0, len(doc.Findings))
	for i, lf := range doc.Findings {
		if strings.TrimSpace(lf.Title) == "" || strings.TrimSpace(lf.Severity) == "" || lf.Description == "" {
			return nil, fmt.Errorf("finding %d: title, severity and description are required", i)
		}
		sev := normalizeSeverity(lf.Severity)
		if !validSeverity(string(sev)) {
			return nil, fmt.Errorf("finding %d: unknown severity %q", i, lf.Severity)
		}
		f := model.Finding{
			Title:            lf.Title,
			Severity:         sev,
			Description:      lf.Description,
			Observed:         lf.Observed,
			UniqueIDFromTool: lf.UniqueIDFromTool,
			VulnIDFromTool:   lf.VulnIDFromTool,
			Tags:             lf.Tags,
			CWE:              lenientCWE(lf.CWE),
			Mitigation:       lf.Mitigation,
			References:       lf.References,
		}
		if lf.Date != "" {
			d, err := parseDate(lf.Date)
			if err != nil {
				return nil, fmt.Errorf("finding %d: %w", i, err)
			}
			f.Date = d
		}
		for j, raw := range lf.Endpoints {
			k, err := parseEndpoint(raw)
			if err != nil {
				return nil, fmt.Errorf("finding %d endpoint %d: %w", i, j, err)
			}
			f.Endpoints = append(f.Endpoints, k)
		}
		out = append(out, f)
	}
	return out, nil
}

// lenientCWE reads a cwe given as a number, a numeric string or "CWE-306";
// anything else is 0.
func lenientCWE(raw json.RawMessage) int {
	s := strings.Trim(strings.TrimSpace(string(raw)), `"`)
	s = strings.TrimPrefix(strings.ToUpper(s), "CWE-")
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 {
		return 0
	}
	return n
}

// endpointFromKey converts an asset key to a DefectDojo endpoint. The
// protocol is a URL scheme for well-known web ports and the transport
// protocol otherwise; a virtual host, when present, is the endpoint host.
func endpointFromKey(k model.AssetKey) wireEndpoint {
	e := wireEndpoint{Host: k.IP.String(), Port: int(k.Port)}
	if k.VHost != "" {
		e.Host = k.VHost
	}
	e.Protocol = schemeFor(k.Port, k.Proto)
	return e
}

var httpsPorts = map[uint16]bool{443: true, 8443: true, 9443: true}
var httpPorts = map[uint16]bool{80: true, 8000: true, 8008: true, 8080: true, 8888: true}

func schemeFor(port uint16, proto string) string {
	proto = strings.ToLower(proto)
	if proto == "udp" {
		return "udp"
	}
	switch {
	case httpsPorts[port]:
		return "https"
	case httpPorts[port]:
		return "http"
	case proto == "":
		return ""
	}
	return "tcp"
}

// parseEndpoint accepts both forms the generic parser accepts: an object
// {"host","port","protocol",...} or a URI string ("https://h:443/p", "h:80").
func parseEndpoint(raw json.RawMessage) (model.AssetKey, error) {
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return parseEndpointURI(s)
	}
	var e struct {
		Host     string          `json:"host"`
		Port     json.RawMessage `json:"port"`
		Protocol string          `json:"protocol"`
	}
	if err := json.Unmarshal(raw, &e); err != nil {
		return model.AssetKey{}, fmt.Errorf("endpoint must be an object or string: %w", err)
	}
	port := 0
	if len(e.Port) > 0 && string(e.Port) != "null" {
		ps := strings.Trim(string(e.Port), `"`)
		n, err := strconv.Atoi(ps)
		if err != nil {
			return model.AssetKey{}, fmt.Errorf("bad port %s", e.Port)
		}
		port = n
	}
	return keyFrom(e.Host, port, e.Protocol)
}

func parseEndpointURI(s string) (model.AssetKey, error) {
	scheme := ""
	if i := strings.Index(s, "://"); i >= 0 {
		scheme, s = s[:i], s[i+3:]
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	host, port := s, 0
	if h, p, ok := splitHostPort(s); ok {
		n, err := strconv.Atoi(p)
		if err != nil {
			return model.AssetKey{}, fmt.Errorf("bad port in %q", s)
		}
		host, port = h, n
	}
	if port == 0 {
		switch strings.ToLower(scheme) {
		case "https":
			port = 443
		case "http":
			port = 80
		}
	}
	return keyFrom(host, port, scheme)
}

func splitHostPort(s string) (host, port string, ok bool) {
	if strings.HasPrefix(s, "[") {
		i := strings.Index(s, "]")
		if i < 0 || i+1 >= len(s) || s[i+1] != ':' {
			return strings.Trim(s, "[]"), "", false
		}
		return s[1:i], s[i+2:], true
	}
	if strings.Count(s, ":") != 1 {
		return s, "", false
	}
	i := strings.LastIndexByte(s, ':')
	return s[:i], s[i+1:], true
}

// keyFrom builds an asset key; a non-IP host is kept as VHost with an
// invalid (zero) IP, which callers may resolve or reject.
func keyFrom(host string, port int, protocol string) (model.AssetKey, error) {
	host = strings.TrimSpace(host)
	if host == "" {
		return model.AssetKey{}, fmt.Errorf("endpoint host is empty")
	}
	if port < 0 || port > 65535 {
		return model.AssetKey{}, fmt.Errorf("port %d out of range", port)
	}
	k := model.AssetKey{Port: uint16(port), Proto: protoFromScheme(protocol)}
	if port == 0 {
		k.Proto = ""
	}
	if a, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
		k.IP = a.Unmap()
	} else {
		k.VHost = strings.ToLower(host)
	}
	return k, nil
}

func protoFromScheme(s string) string {
	if strings.EqualFold(s, "udp") {
		return "udp"
	}
	return "tcp"
}

func parseDate(s string) (time.Time, error) {
	for _, layout := range []string{dateLayout, time.RFC3339, time.RFC3339Nano, "2006-01-02T15:04:05"} {
		if t, err := time.Parse(layout, s); err == nil {
			return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC), nil
		}
	}
	return time.Time{}, fmt.Errorf("bad date %q", s)
}

// normalizeSeverity maps common spellings to DefectDojo severities.
func normalizeSeverity(s string) model.Severity {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "info", "informational", "information", "none":
		return model.SevInfo
	case "low":
		return model.SevLow
	case "medium", "moderate":
		return model.SevMedium
	case "high":
		return model.SevHigh
	case "critical":
		return model.SevCritical
	}
	return model.Severity(s)
}

func validSeverity(s string) bool {
	switch model.Severity(s) {
	case model.SevInfo, model.SevLow, model.SevMedium, model.SevHigh, model.SevCritical:
		return true
	}
	return false
}

// normalizeTags lowercases, trims, removes empty and duplicate tags and
// sorts them so that output is deterministic.
func normalizeTags(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, t := range in {
		t = strings.ToLower(strings.TrimSpace(t))
		t = strings.ReplaceAll(t, " ", "-")
		if t == "" || seen[t] {
			continue
		}
		seen[t] = true
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}
