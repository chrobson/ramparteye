package dojo

import (
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/chrobson/ramparteye/internal/model"
)

// HTTPSummary is the part of an HTTP observation shown in findings.
type HTTPSummary struct {
	URL    string `json:"url"`
	Status int    `json:"status"`
	Title  string `json:"title"`
}

// Service is one service of a run with everything needed for exports.
type Service struct {
	model.ServiceObs
	Hostname   string            `json:"hostname,omitempty"`
	HTTP       *HTTPSummary      `json:"http,omitempty"`
	Detections []model.Detection `json:"detections,omitempty"`
}

// Annotation is an analyst edit keyed by the natural asset key. Port 0 is a
// host-level annotation that applies to every service of the host.
type Annotation struct {
	Key           model.AssetKey
	Comment       string
	Tags          []string
	Severity      string // "" = no override
	FalsePositive bool
}

// Unique ID prefixes; they match the model.Finding.UniqueIDFromTool contract.
const (
	svcPrefix = "rampart:svc:"
	sigPrefix = "rampart:sig:"
)

// UniqueServiceID returns rampart:svc:<ip>:<port>/<proto>, suffixed with
// @<vhost> when the service was probed on a virtual host.
func UniqueServiceID(k model.AssetKey) string {
	s := fmt.Sprintf(svcPrefix+"%s:%d/%s", k.IP, k.Port, k.Proto)
	if k.VHost != "" {
		s += "@" + k.VHost
	}
	return s
}

// UniqueSignatureID returns rampart:sig:<ip>:<port>:<sig_id>, suffixed with
// @<vhost> when the service was probed on a virtual host.
func UniqueSignatureID(k model.AssetKey, sigID string) string {
	s := fmt.Sprintf(sigPrefix+"%s:%d:%s", k.IP, k.Port, sigID)
	if k.VHost != "" {
		s += "@" + k.VHost
	}
	return s
}

// ParseUniqueID extracts the IP and port from a RampartEye unique_id_from_tool.
// It is used on import when an endpoint carries a virtual host instead of
// the IP address.
func ParseUniqueID(uid string) (ip netip.Addr, port uint16, ok bool) {
	var rest string
	switch {
	case strings.HasPrefix(uid, svcPrefix):
		rest = strings.TrimPrefix(uid, svcPrefix)
		if i := strings.LastIndexByte(rest, '/'); i >= 0 {
			rest = rest[:i]
		} else {
			return ip, 0, false
		}
	case strings.HasPrefix(uid, sigPrefix):
		rest = strings.TrimPrefix(uid, sigPrefix)
		i := strings.LastIndexByte(rest, ':')
		if i < 0 {
			return ip, 0, false
		}
		rest = rest[:i]
	default:
		return ip, 0, false
	}
	i := strings.LastIndexByte(rest, ':')
	if i < 0 {
		return ip, 0, false
	}
	a, err := netip.ParseAddr(rest[:i])
	if err != nil {
		return ip, 0, false
	}
	p, err := strconv.ParseUint(rest[i+1:], 10, 16)
	if err != nil {
		return ip, 0, false
	}
	return a, uint16(p), true
}

// BuildFindings turns the services of one run into findings: one Info
// finding per service and one finding per detection (admin panels and
// staging environments Medium, other technologies Info). Annotations marked
// false_positive drop the finding; a severity override replaces the default
// severity; analyst tags and comments are carried over. Titles never contain
// timestamps or run ids, so DefectDojo deduplication stays stable.
func BuildFindings(date time.Time, svcs []Service, anns []Annotation) []model.Finding {
	byKey := make(map[model.AssetKey]Annotation, len(anns))
	for _, a := range anns {
		a.Key = annotationKey(a.Key)
		byKey[a.Key] = a
	}
	day := time.Date(date.Year(), date.Month(), date.Day(), 0, 0, 0, 0, time.UTC)
	if date.IsZero() {
		day = time.Time{}
	}

	var out []model.Finding
	seen := map[string]bool{}
	emit := func(f model.Finding) {
		if seen[f.UniqueIDFromTool] {
			return
		}
		seen[f.UniqueIDFromTool] = true
		out = append(out, f)
	}
	for _, s := range svcs {
		k := s.Key
		k.IP = k.IP.Unmap()
		host := byKey[model.AssetKey{IP: k.IP}]
		svc := byKey[k]
		if host.FalsePositive || svc.FalsePositive {
			continue
		}
		override := firstNonEmpty(svc.Severity, host.Severity)
		annTags := append(append([]string{}, host.Tags...), svc.Tags...)
		comments := nonEmpty(host.Comment, svc.Comment)

		sev := model.SevInfo
		if o := normalizeSeverity(override); validSeverity(string(o)) {
			sev = o
		}
		emit(model.Finding{
			Title:            serviceTitle(s),
			Severity:         sev,
			Description:      serviceDescription(s, comments),
			Date:             day,
			UniqueIDFromTool: UniqueServiceID(k),
			Endpoints:        []model.AssetKey{k},
			Tags:             normalizeTags(append([]string{"rampart", "service"}, annTags...)),
		})

		dets := append([]model.Detection(nil), s.Detections...)
		sort.Slice(dets, func(i, j int) bool { return dets[i].SignatureID < dets[j].SignatureID })
		for _, d := range dets {
			sev := DetectionSeverity(d)
			if o := normalizeSeverity(override); validSeverity(string(o)) {
				sev = o
			}
			cat := d.Category
			if cat == "" {
				cat = "other"
			}
			f := model.Finding{
				Title:            detectionTitle(d),
				Severity:         sev,
				Description:      detectionDescription(s, d, comments),
				Date:             day,
				UniqueIDFromTool: UniqueSignatureID(k, d.SignatureID),
				VulnIDFromTool:   d.SignatureID,
				Endpoints:        []model.AssetKey{k},
			}
			tags := append([]string{"rampart", cat}, annTags...)
			if m := d.Meta; m != nil {
				if len(m.CWE) > 0 {
					f.CWE = m.CWE[0]
				}
				f.Mitigation = m.Remediation
				f.References = references(m)
				for _, a := range m.Attack {
					tags = append(tags, "attack-"+a)
				}
			}
			f.Tags = normalizeTags(tags)
			emit(f)
		}
	}
	return out
}

// references lists the signature's own URLs followed by the MITRE pages of
// its CWE ids and ATT&CK techniques, one per line, without duplicates.
func references(m *model.SignatureMeta) string {
	var refs []string
	seen := map[string]bool{}
	add := func(u string) {
		if u = strings.TrimSpace(u); u != "" && !seen[u] {
			seen[u] = true
			refs = append(refs, u)
		}
	}
	for _, u := range m.References {
		add(u)
	}
	for _, c := range m.CWE {
		add(fmt.Sprintf("https://cwe.mitre.org/data/definitions/%d.html", c))
	}
	for _, a := range m.Attack {
		add("https://attack.mitre.org/techniques/" + strings.ReplaceAll(a, ".", "/") + "/")
	}
	return strings.Join(refs, "\n")
}

// annotationKey normalises an annotation key: IPv4-mapped addresses are
// unmapped and a host-level annotation (port 0) matches on the IP only,
// whatever proto/vhost it was stored with.
func annotationKey(k model.AssetKey) model.AssetKey {
	k.IP = k.IP.Unmap()
	if k.Port == 0 {
		return model.AssetKey{IP: k.IP}
	}
	return k
}

// AnnotationKey exposes annotationKey to the export package.
func AnnotationKey(k model.AssetKey) model.AssetKey { return annotationKey(k) }

// DetectionSeverity is the default severity of a detection: the severity
// the signature recorded in evidence["severity"] (its own level, or the
// raised level of an outdated version), otherwise Medium for admin panels
// and staging environments and Info for other technologies.
func DetectionSeverity(d model.Detection) model.Severity {
	if s := normalizeSeverity(d.Evidence["severity"]); validSeverity(string(s)) {
		return s
	}
	return detectionSeverity(d.Category)
}

func detectionSeverity(category string) model.Severity {
	switch category {
	case "admin-panel", "staging":
		return model.SevMedium
	}
	return model.SevInfo
}

func serviceTitle(s Service) string {
	t := fmt.Sprintf("Open service %d/%s", s.Key.Port, s.Key.Proto)
	if p := strings.TrimSpace(strings.TrimSpace(s.Product) + " " + strings.TrimSpace(s.Version)); p != "" {
		t += " " + p
	}
	return oneLine(t)
}

func detectionTitle(d model.Detection) string {
	name := d.Name
	if name == "" {
		name = d.SignatureID
	}
	if d.Evidence["outdated"] != "" && d.Evidence["version"] != "" {
		return oneLine("Outdated software detected: " + name + " " + d.Evidence["version"])
	}
	switch d.Category {
	case "admin-panel":
		return oneLine("Admin panel detected: " + name)
	case "staging":
		return oneLine("Staging environment detected: " + name)
	}
	return oneLine("Technology detected: " + name)
}

func serviceDescription(s Service, comments []string) string {
	var b strings.Builder
	b.WriteString("Service detected by RampartEye.\n\n")
	writeAssetLines(&b, s)
	line(&b, "Product", s.Product)
	line(&b, "Version", s.Version)
	line(&b, "Extra info", s.ExtraInfo)
	line(&b, "CPE", s.CPE)
	writeHTTPLines(&b, s.HTTP)
	if len(s.Detections) > 0 {
		names := make([]string, 0, len(s.Detections))
		for _, d := range s.Detections {
			names = append(names, d.Name)
		}
		sort.Strings(names)
		line(&b, "Technologies", strings.Join(names, ", "))
	}
	// The raw banner is deliberately left out: banners often carry per
	// connection noise (SMTP dates, client ids), and DefectDojo's default
	// hash for "Generic Findings Import" covers title and description, so a
	// changing banner would close and recreate the finding on every reimport.
	writeComments(&b, comments)
	return strings.TrimRight(b.String(), "\n")
}

func detectionDescription(s Service, d model.Detection, comments []string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Signature `%s` matched.\n\n", d.SignatureID)
	writeAssetLines(&b, s)
	line(&b, "Category", d.Category)
	line(&b, "Confidence", strconv.Itoa(d.Confidence)+"%")
	writeHTTPLines(&b, s.HTTP)
	if len(d.Evidence) > 0 {
		b.WriteString("\nEvidence:\n\n")
		ks := make([]string, 0, len(d.Evidence))
		for k := range d.Evidence {
			ks = append(ks, k)
		}
		sort.Strings(ks)
		for _, k := range ks {
			fmt.Fprintf(&b, "- %s: %s\n", k, oneLine(d.Evidence[k]))
		}
	}
	writeComments(&b, comments)
	return strings.TrimRight(b.String(), "\n")
}

func writeAssetLines(b *strings.Builder, s Service) {
	line(b, "Host", s.Key.IP.String())
	line(b, "Hostname", s.Hostname)
	line(b, "Virtual host", s.Key.VHost)
	line(b, "Port", fmt.Sprintf("%d/%s", s.Key.Port, s.Key.Proto))
}

func writeHTTPLines(b *strings.Builder, h *HTTPSummary) {
	if h == nil {
		return
	}
	line(b, "URL", h.URL)
	if h.Status != 0 {
		line(b, "HTTP status", strconv.Itoa(h.Status))
	}
	line(b, "Page title", h.Title)
}

func writeComments(b *strings.Builder, comments []string) {
	for _, c := range comments {
		b.WriteString("\nAnalyst comment:\n\n> " + strings.ReplaceAll(strings.TrimSpace(c), "\n", "\n> ") + "\n")
	}
}

func line(b *strings.Builder, label, v string) {
	if v = oneLine(v); v != "" {
		fmt.Fprintf(b, "- %s: %s\n", label, v)
	}
}

func oneLine(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if strings.TrimSpace(s) != "" {
			return s
		}
	}
	return ""
}

func nonEmpty(ss ...string) []string {
	var out []string
	for _, s := range ss {
		if strings.TrimSpace(s) != "" {
			out = append(out, s)
		}
	}
	return out
}
