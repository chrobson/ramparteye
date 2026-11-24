// Package exchange renders scan results as CSV, JSON and DefectDojo Generic
// Findings, and imports nmap XML and Generic Findings JSON as scan runs of
// kind "import". Exports are generated on demand into a writer; nothing is
// written to disk.
package exchange

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/chrobson/ramparteye/internal/dojo"
	"github.com/chrobson/ramparteye/internal/model"
	"github.com/chrobson/ramparteye/internal/scan"
)

const (
	// MaxImportSize caps an uploaded import file (kept in memory only).
	MaxImportSize = 32 << 20

	maxField        = scan.MaxFieldBytes // text taken from an imported file
	maxEvidence     = 32                 // evidence entries kept per detection
	maxEvidenceKey  = 64
	maxEvidenceItem = 256
)

// Format of an import file.
type Format string

const (
	FormatUnknown Format = ""
	FormatNmapXML Format = "nmap-xml"
	FormatGeneric Format = "generic-findings"
)

var (
	// ErrUnknownFormat is returned for files that are neither nmap XML nor
	// Generic Findings JSON.
	ErrUnknownFormat = errors.New("unknown import format: expected nmap XML or DefectDojo Generic Findings JSON")
	// ErrTooLarge is returned for a file larger than MaxImportSize.
	ErrTooLarge = fmt.Errorf("import file is larger than %d MiB", MaxImportSize>>20)
)

// Observations is the parsed content of an import file.
type Observations struct {
	Hosts      []model.HostObs
	Services   []model.ServiceObs
	Detections []ImportedDetection
	Errors     []string
}

// ImportedDetection is a detection attached to a service by asset key.
type ImportedDetection struct {
	Key model.AssetKey
	model.Detection
}

// DetectFormat sniffs the file content.
func DetectFormat(b []byte) Format {
	t := bytes.TrimSpace(bytes.TrimPrefix(b, []byte("\xef\xbb\xbf")))
	switch {
	case bytes.HasPrefix(t, []byte("<")) && bytes.Contains(t[:min(len(t), 4096)], []byte("<nmaprun")):
		return FormatNmapXML
	case bytes.HasPrefix(t, []byte("{")) && bytes.Contains(t, []byte(`"findings"`)):
		return FormatGeneric
	}
	return FormatUnknown
}

// Parse converts an import file to observations without touching the
// database. nmap XML goes through scan.Parse (same size and field caps as a
// live scan); Generic Findings JSON must pass dojo.Validate and is decoded
// with the dojo codec.
func Parse(b []byte) (Format, Observations, error) {
	if len(b) > MaxImportSize {
		return FormatUnknown, Observations{}, ErrTooLarge
	}
	switch f := DetectFormat(b); f {
	case FormatNmapXML:
		res, err := scan.Parse(bytes.NewReader(b))
		if err != nil {
			return f, Observations{}, err
		}
		return f, Observations{Hosts: res.Hosts, Services: res.Services}, nil
	case FormatGeneric:
		if err := dojo.Validate(b); err != nil {
			return f, Observations{}, fmt.Errorf("invalid Generic Findings file: %w", err)
		}
		fs, err := dojo.NewCodec().Unmarshal(b)
		if err != nil {
			return f, Observations{}, err
		}
		return f, FromFindings(fs), nil
	}
	return FormatUnknown, Observations{}, ErrUnknownFormat
}

const (
	svcPrefix = "rampart:svc:"
	sigPrefix = "rampart:sig:"
)

var titlePrefixes = []struct{ prefix, category string }{
	{"Admin panel detected: ", "admin-panel"},
	{"Staging environment detected: ", "staging"},
	{"Outdated software detected: ", ""},
	{"Technology detected: ", ""},
}

var knownCategories = map[string]bool{
	"cms": true, "framework": true, "server": true, "iot": true,
	"admin-panel": true, "staging": true, "other": true,
}

var knownProtos = map[string]bool{"tcp": true, "udp": true, "sctp": true}

// FromFindings maps Generic Findings to observations. A finding with a
// vuln_id_from_tool (or a rampart:sig: unique id) becomes a detection on
// its endpoints, anything else a service. Endpoints whose host is not an IP
// address are resolved from a RampartEye unique id when possible, otherwise
// they are reported and skipped (imports never perform DNS lookups). Text
// from the file is bounded and valid UTF-8; the observed data of a finding
// (steps_to_reproduce) restores hostname, product, version, extra info,
// CPE, confidence and evidence.
func FromFindings(fs []model.Finding) Observations {
	var obs Observations
	hostAt := map[netip.Addr]int{}
	svcSeen := map[model.AssetKey]int{}
	addHost := func(ip netip.Addr, hostname string) {
		if i, ok := hostAt[ip]; ok {
			if obs.Hosts[i].Hostname == "" {
				obs.Hosts[i].Hostname = hostname
			}
			return
		}
		hostAt[ip] = len(obs.Hosts)
		obs.Hosts = append(obs.Hosts, model.HostObs{IP: ip, Hostname: hostname, Up: true})
	}
	addSvc := func(s model.ServiceObs) {
		if i, dup := svcSeen[s.Key]; dup {
			// Fill gaps of an earlier record for the same key.
			o := &obs.Services[i]
			if o.Product == "" {
				o.Product, o.Version = s.Product, s.Version
			}
			if o.ExtraInfo == "" {
				o.ExtraInfo = s.ExtraInfo
			}
			if o.CPE == "" {
				o.CPE = s.CPE
			}
			return
		}
		svcSeen[s.Key] = len(obs.Services)
		obs.Services = append(obs.Services, s)
	}

	for i, f := range fs {
		title := clip(strings.TrimSpace(f.Title), maxField)
		sigID := clip(f.VulnIDFromTool, maxField)
		if sigID == "" && strings.HasPrefix(f.UniqueIDFromTool, sigPrefix) {
			if j := strings.LastIndexByte(f.UniqueIDFromTool, ':'); j >= 0 {
				sigID = clip(strings.SplitN(f.UniqueIDFromTool[j+1:], "@", 2)[0], maxField)
			}
		}
		if len(f.Endpoints) == 0 {
			obs.Errors = append(obs.Errors, fmt.Sprintf("finding %d (%q): no endpoints, skipped", i, title))
			continue
		}
		fields, evidence := parseObserved(f.Observed)
		for _, k := range f.Endpoints {
			if !k.IP.IsValid() {
				ip, port, ok := dojo.ParseUniqueID(f.UniqueIDFromTool)
				if !ok {
					obs.Errors = append(obs.Errors, fmt.Sprintf("finding %d (%q): host %q is not an IP address, skipped",
						i, title, clip(k.VHost, 128)))
					continue
				}
				k.IP = ip
				if k.Port == 0 {
					k.Port = port
				}
				if k.Proto == "" && k.Port != 0 {
					k.Proto = "tcp"
				}
			}
			k.IP = k.IP.Unmap()
			k.Proto = strings.ToLower(k.Proto)
			k.VHost = clip(k.VHost, maxField)
			if k.Port == 0 || !knownProtos[k.Proto] {
				obs.Errors = append(obs.Errors, fmt.Sprintf("finding %d (%q): endpoint without a usable port or protocol, skipped", i, title))
				continue
			}
			addHost(k.IP, fields["Hostname"])
			if sigID == "" {
				svc := model.ServiceObs{Key: k, Product: fields["Product"], Version: fields["Version"],
					ExtraInfo: fields["Extra info"], CPE: fields["CPE"]}
				// Our own export writes the product in the observed data;
				// the title of a foreign finding is the best product guess.
				if svc.Product == "" && !strings.HasPrefix(f.UniqueIDFromTool, "rampart:") {
					svc.Product = title
				}
				addSvc(svc)
				continue
			}
			addSvc(model.ServiceObs{Key: k})
			name, cat := title, ""
			for _, p := range titlePrefixes {
				if strings.HasPrefix(name, p.prefix) {
					name, cat = strings.TrimPrefix(name, p.prefix), p.category
					break
				}
			}
			if cat == "" {
				for _, t := range f.Tags {
					if knownCategories[strings.ToLower(t)] {
						cat = strings.ToLower(t)
						break
					}
				}
			}
			if cat == "" {
				cat = "other"
			}
			ev := map[string]string{"source": "import"}
			for k, v := range evidence {
				if k != "source" {
					ev[k] = v
				}
			}
			obs.Detections = append(obs.Detections, ImportedDetection{Key: k, Detection: model.Detection{
				SignatureID: sigID, Name: name, Category: cat, Confidence: confidence(fields["Confidence"]),
				Evidence: ev,
			}})
		}
	}
	return obs
}

// confidence reads "90%"; anything unusable is full confidence.
func confidence(s string) int {
	n, err := strconv.Atoi(strings.TrimSuffix(strings.TrimSpace(s), "%"))
	if err != nil || n < 0 || n > 100 {
		return 100
	}
	return n
}

// parseObserved reads the steps_to_reproduce text written by
// dojo.BuildFindings: "- Label: `value`" lines, then an "Evidence:" list of
// "- `key`: `value`" lines. Every value is bounded and valid UTF-8.
func parseObserved(s string) (fields, evidence map[string]string) {
	fields, evidence = map[string]string{}, map[string]string{}
	inEvidence := false
	for _, l := range strings.Split(s, "\n") {
		l = strings.TrimSpace(l)
		switch {
		case l == "Evidence:":
			inEvidence = true
		case strings.HasPrefix(l, "- "):
			label, v, ok := strings.Cut(l[2:], ": ")
			if !ok {
				continue
			}
			if inEvidence {
				if len(evidence) < maxEvidence {
					if k := unquote(label, maxEvidenceKey); k != "" {
						evidence[k] = unquote(v, maxEvidenceItem)
					}
				}
			} else if _, dup := fields[label]; !dup && len(fields) < 32 {
				fields[clip(label, maxEvidenceKey)] = unquote(v, maxField)
			}
		}
	}
	return fields, evidence
}

// unquote strips the Markdown code span dojo.BuildFindings wraps values in.
func unquote(s string, max int) string {
	s = strings.TrimSpace(s)
	n := 0
	for n < len(s) && s[n] == '`' {
		n++
	}
	if n > 0 && len(s) >= 2*n && strings.HasSuffix(s, strings.Repeat("`", n)) {
		inner := s[n : len(s)-n]
		if len(inner) >= 2 && inner[0] == ' ' && inner[len(inner)-1] == ' ' {
			inner = inner[1 : len(inner)-1]
		}
		s = inner
	}
	return clip(s, max)
}

// clip returns s as valid UTF-8 without NUL bytes (PostgreSQL rejects
// them), cut to at most n bytes on a rune boundary.
func clip(s string, n int) string {
	s = strings.ToValidUTF8(s, "")
	s = strings.ReplaceAll(s, "\x00", "")
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}
