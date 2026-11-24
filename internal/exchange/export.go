package exchange

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/chrobson/ramparteye/internal/dojo"
	"github.com/chrobson/ramparteye/internal/model"
	"github.com/chrobson/ramparteye/internal/sig"
	"github.com/chrobson/ramparteye/internal/store"
)

// Snapshot is everything an export is built from: one run's services and
// the current analyst annotations.
type Snapshot struct {
	RunID       int64
	RunKind     string
	Date        time.Time
	Services    []dojo.Service
	Annotations []dojo.Annotation
}

// LoadSnapshot reads one finished run (runID 0 = the latest) with its
// services, detections and the annotations of its hosts, and attaches the
// signature metadata to the detections.
func LoadSnapshot(ctx context.Context, st *store.Store, runID int64) (Snapshot, error) {
	run, err := st.DojoRun(ctx, runID)
	if err != nil {
		return Snapshot{}, err
	}
	metas := sig.Metas(ctx, st)
	svcs := make([]dojo.Service, len(run.Services))
	for i, sv := range run.Services {
		svcs[i] = dojo.Service{ServiceObs: sv.ServiceObs, Hostname: sv.Hostname,
			Detections: append([]model.Detection(nil), sv.Detections...)}
		if sv.HTTP != nil {
			svcs[i].HTTP = &dojo.HTTPSummary{URL: sv.HTTP.URL, Status: sv.HTTP.Status, Title: sv.HTTP.Title}
		}
		model.AttachMeta(svcs[i].Detections, metas)
	}
	anns := make([]dojo.Annotation, len(run.Annotations))
	for i, a := range run.Annotations {
		anns[i] = dojo.Annotation{Key: a.Key, Comment: a.Comment, Tags: a.Tags, Severity: a.Severity,
			FalsePositive: a.FalsePositive}
	}
	return Snapshot{RunID: run.Run.ID, RunKind: run.Run.Kind, Date: run.Run.Date(), Services: svcs, Annotations: anns}, nil
}

// Findings builds the DefectDojo findings of the snapshot.
func (s Snapshot) Findings() []model.Finding {
	return dojo.BuildFindings(s.Date, s.Services, s.Annotations)
}

// Dojo returns the Generic Findings JSON document of the snapshot.
func (s Snapshot) Dojo() ([]byte, error) {
	return dojo.NewCodec().Marshal(s.Findings())
}

// annotationFor returns the effective annotation of a service: the service
// annotation merged over the host-level one.
func (s Snapshot) annotationFor(k model.AssetKey) (dojo.Annotation, bool) {
	var host, svc dojo.Annotation
	var hostOK, svcOK bool
	k.IP = k.IP.Unmap()
	for _, a := range s.Annotations {
		ak := dojo.AnnotationKey(a.Key)
		switch {
		case ak == k:
			svc, svcOK = a, true
		case ak == model.AssetKey{IP: k.IP}:
			host, hostOK = a, true
		}
	}
	if !hostOK && !svcOK {
		return dojo.Annotation{}, false
	}
	out := svc
	out.Key = k
	out.FalsePositive = host.FalsePositive || svc.FalsePositive
	if out.Severity == "" {
		out.Severity = host.Severity
	}
	out.Tags = append(append([]string{}, host.Tags...), svc.Tags...)
	out.Comment = strings.TrimSpace(strings.Join([]string{host.Comment, svc.Comment}, "\n"))
	return out, true
}

// ServiceRecord is one service in the JSON export.
type ServiceRecord struct {
	IP         string            `json:"ip"`
	Hostname   string            `json:"hostname,omitempty"`
	Port       uint16            `json:"port"`
	Proto      string            `json:"proto"`
	VHost      string            `json:"vhost,omitempty"`
	Product    string            `json:"product,omitempty"`
	Version    string            `json:"version,omitempty"`
	ExtraInfo  string            `json:"extrainfo,omitempty"`
	CPE        string            `json:"cpe,omitempty"`
	Banner     string            `json:"banner,omitempty"`
	HTTP       *dojo.HTTPSummary `json:"http,omitempty"`
	Detections []DetectionRecord `json:"detections"`
	Annotation *AnnotationRecord `json:"annotation,omitempty"`
}

// DetectionRecord is one detection in the JSON export.
type DetectionRecord struct {
	SignatureID string            `json:"signature_id"`
	Name        string            `json:"name"`
	Category    string            `json:"category"`
	Confidence  int               `json:"confidence"`
	Evidence    map[string]string `json:"evidence,omitempty"`
}

// AnnotationRecord is the effective analyst annotation of a service.
type AnnotationRecord struct {
	Comment       string   `json:"comment,omitempty"`
	Tags          []string `json:"tags,omitempty"`
	Severity      string   `json:"severity,omitempty"`
	FalsePositive bool     `json:"false_positive"`
}

// Document is the JSON export.
type Document struct {
	Tool     string          `json:"tool"`
	RunID    int64           `json:"run_id"`
	RunKind  string          `json:"run_kind,omitempty"`
	Date     string          `json:"date"`
	Services []ServiceRecord `json:"services"`
}

// Records converts the snapshot to export records (stable order).
func (s Snapshot) Records() []ServiceRecord {
	svcs := append([]dojo.Service(nil), s.Services...)
	sort.SliceStable(svcs, func(i, j int) bool { return lessKey(svcs[i].Key, svcs[j].Key) })
	out := make([]ServiceRecord, 0, len(svcs))
	for _, sv := range svcs {
		r := ServiceRecord{
			IP: sv.Key.IP.String(), Hostname: sv.Hostname, Port: sv.Key.Port, Proto: sv.Key.Proto,
			VHost: sv.Key.VHost, Product: sv.Product, Version: sv.Version, ExtraInfo: sv.ExtraInfo,
			CPE: sv.CPE, Banner: sv.Banner, HTTP: sv.HTTP, Detections: []DetectionRecord{},
		}
		dets := append([]model.Detection(nil), sv.Detections...)
		sort.Slice(dets, func(i, j int) bool { return dets[i].SignatureID < dets[j].SignatureID })
		for _, d := range dets {
			r.Detections = append(r.Detections, DetectionRecord{
				SignatureID: d.SignatureID, Name: d.Name, Category: d.Category,
				Confidence: d.Confidence, Evidence: d.Evidence,
			})
		}
		if a, ok := s.annotationFor(sv.Key); ok {
			r.Annotation = &AnnotationRecord{Comment: a.Comment, Tags: a.Tags, Severity: a.Severity, FalsePositive: a.FalsePositive}
		}
		out = append(out, r)
	}
	return out
}

func lessKey(a, b model.AssetKey) bool {
	if c := a.IP.Compare(b.IP); c != 0 {
		return c < 0
	}
	if a.Port != b.Port {
		return a.Port < b.Port
	}
	if a.Proto != b.Proto {
		return a.Proto < b.Proto
	}
	return a.VHost < b.VHost
}

// WriteJSON streams the JSON export.
func WriteJSON(w io.Writer, s Snapshot) error {
	doc := Document{
		Tool: "ramparteye", RunID: s.RunID, RunKind: s.RunKind,
		Date: s.Date.UTC().Format(time.RFC3339), Services: s.Records(),
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

// CSVHeader is the column list of the CSV export.
var CSVHeader = []string{
	"ip", "hostname", "port", "proto", "vhost", "product", "version", "extrainfo", "cpe",
	"url", "http_status", "http_title", "detections", "categories",
	"severity", "false_positive", "tags", "comment",
}

// WriteCSV streams the CSV export: one row per service, detections joined
// with ";". Cells that a spreadsheet would treat as formulas are prefixed
// with a quote (CSV injection).
func WriteCSV(w io.Writer, s Snapshot) error {
	cw := csv.NewWriter(w)
	if err := cw.Write(CSVHeader); err != nil {
		return err
	}
	for _, r := range s.Records() {
		var url, status, title string
		if r.HTTP != nil {
			url, title = r.HTTP.URL, r.HTTP.Title
			if r.HTTP.Status != 0 {
				status = strconv.Itoa(r.HTTP.Status)
			}
		}
		var dets, cats []string
		catSeen := map[string]bool{}
		for _, d := range r.Detections {
			dets = append(dets, d.SignatureID)
			if !catSeen[d.Category] && d.Category != "" {
				catSeen[d.Category] = true
				cats = append(cats, d.Category)
			}
		}
		sort.Strings(cats)
		var sev, fp, tags, comment string
		fp = "false"
		if a := r.Annotation; a != nil {
			sev, tags, comment = a.Severity, strings.Join(a.Tags, ";"), a.Comment
			fp = strconv.FormatBool(a.FalsePositive)
		}
		row := []string{
			r.IP, r.Hostname, strconv.Itoa(int(r.Port)), r.Proto, r.VHost, r.Product, r.Version,
			r.ExtraInfo, r.CPE, url, status, title, strings.Join(dets, ";"), strings.Join(cats, ";"),
			sev, fp, tags, comment,
		}
		for i := range row {
			row[i] = safeCell(row[i])
		}
		if err := cw.Write(row); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

// safeCell neutralises spreadsheet formula injection and replaces invalid
// UTF-8 in text that comes from scanned hosts. Spreadsheets skip leading
// whitespace and control characters before reading a formula, so the first
// character that is neither decides, as does the very first byte.
func safeCell(s string) string {
	s = strings.ToValidUTF8(s, "\uFFFD")
	if s == "" {
		return s
	}
	switch s[0] {
	case '=', '+', '-', '@', '\t', '\r':
		return "'" + s
	}
	for _, r := range s {
		if unicode.IsSpace(r) || unicode.IsControl(r) || r == '\u00a0' {
			continue
		}
		if r == '=' || r == '+' || r == '-' || r == '@' {
			return "'" + s
		}
		break
	}
	return s
}
