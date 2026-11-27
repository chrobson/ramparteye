// Package summary turns the stored result of a run into what a person reads
// first: the change counts, the plain-language headline and the services
// ranked by interest score. The dashboard and the webhook notifications
// share it, so both say the same thing about a run.
package summary

import (
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/chrobson/ramparteye/internal/dojo"
	"github.com/chrobson/ramparteye/internal/interest"
	"github.com/chrobson/ramparteye/internal/model"
	"github.com/chrobson/ramparteye/internal/store"
)

// UrgentMin is the interest score from which a service needs attention now
// (interest priority "high").
const UrgentMin = 60

// Counts are the changes of a run against its predecessor, by kind.
type Counts struct {
	NewHosts, HostsGone, NewServices, ServicesGone, Changed, Unstable int
}

// Total is the number of changes.
func (c Counts) Total() int {
	return c.NewHosts + c.HostsGone + c.NewServices + c.ServicesGone + c.Changed + c.Unstable
}

func (c *Counts) add(k model.ChangeKind, n int) {
	switch k {
	case model.ChangeNew:
		c.NewServices += n
	case model.ChangeGone:
		c.ServicesGone += n
	case model.ChangeChanged:
		c.Changed += n
	case model.ChangeHostUp:
		c.NewHosts += n
	case model.ChangeHostDown:
		c.HostsGone += n
	case model.ChangeUnstable:
		c.Unstable += n
	}
}

// CountChanges counts changes by kind.
func CountChanges(cs []model.Change) Counts {
	var c Counts
	for _, ch := range cs {
		c.add(ch.Kind, 1)
	}
	return c
}

// FromKinds converts per-kind counts (store.ChangeRun.Counts).
func FromKinds(m map[model.ChangeKind]int) Counts {
	var c Counts
	for k, n := range m {
		c.add(k, n)
	}
	return c
}

// Headline returns the headline of a finished run's changes and the line
// saying whether anything needs urgent attention (urgent services, see
// UrgentMin). Counts of zero are left out.
func Headline(c Counts, urgent int) (title, sub string) {
	var parts []string
	if c.NewServices > 0 {
		parts = append(parts, Plural(c.NewServices, "new exposure", "new exposures"))
	}
	if c.HostsGone > 0 {
		parts = append(parts, Plural(c.HostsGone, "host", "hosts")+" gone")
	}
	if c.Changed > 0 {
		parts = append(parts, Plural(c.Changed, "service", "services")+" changed")
	}
	if len(parts) == 0 {
		title = "No changes since the last scan."
	} else {
		title = "Since the last scan: " + strings.Join(parts, ", ") + "."
	}
	if urgent == 0 {
		sub = "Nothing needs urgent attention."
	} else {
		sub = Plural(urgent, "service needs", "services need") + " attention first."
	}
	return title, sub
}

// Plural returns "1 one" or "n many".
func Plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return strconv.Itoa(n) + " " + many
}

// ChangeKinds groups the change kinds of a run by asset key, in change order.
func ChangeKinds(cs []model.Change) map[model.AssetKey][]string {
	out := map[model.AssetKey][]string{}
	for _, c := range cs {
		out[c.Key] = append(out[c.Key], string(c.Kind))
	}
	return out
}

// Ranked is a service with its interest score and the change kinds of its
// key in the run.
type Ranked struct {
	Service store.ExportService
	Score   int
	Kinds   []string
}

// Rank scores every service (interest.Score) and returns them highest score
// first; equal scores keep the input order. unstable holds the unmapped
// addresses of unstable hosts, notes the analyst annotations.
func Rank(svcs []store.ExportService, kinds map[model.AssetKey][]string, unstable map[netip.Addr]bool,
	notes map[model.AssetKey]store.Annotation) []Ranked {
	out := make([]Ranked, len(svcs))
	for i, sv := range svcs {
		k := kinds[sv.Key]
		in := InterestInput(sv, k, unstable[sv.Key.IP.Unmap()], notes[sv.Key])
		out[i] = Ranked{Service: sv, Score: interest.Score(in).Score, Kinds: k}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Score > out[j].Score })
	return out
}

// InterestInput maps a stored service to the scoring input. A detection
// without its own severity gets the DefectDojo export's default. The nmap
// service name is kept in Banner.
func InterestInput(sv store.ExportService, kinds []string, unstable bool, note store.Annotation) interest.Input {
	in := interest.Input{Port: int(sv.Key.Port), Proto: sv.Key.Proto, Service: sv.Banner, Product: sv.Product,
		ChangeKinds: kinds, HostUnstable: unstable, AnalystSeverity: note.Severity, FalsePositive: note.FalsePositive}
	if sv.HTTP != nil {
		switch {
		case strings.HasPrefix(sv.HTTP.URL, "https:"):
			in.Scheme = "https"
		case strings.HasPrefix(sv.HTTP.URL, "http:"):
			in.Scheme = "http"
		}
	}
	for _, d := range sv.Detections {
		switch d.SignatureID {
		case "tls-expired":
			in.TLSExpired = true
		case "tls-self-signed":
			in.TLSSelfSigned = true
		}
		in.Detections = append(in.Detections, interest.Detection{Signature: d.SignatureID, Name: d.Name,
			Category: d.Category, Severity: string(dojo.DetectionSeverity(d)), Confidence: d.Confidence,
			Outdated: d.Evidence["outdated"]})
	}
	return in
}

var severityRank = map[model.Severity]int{model.SevInfo: 0, model.SevLow: 1, model.SevMedium: 2,
	model.SevHigh: 3, model.SevCritical: 4}

// Strongest returns the index of the detection with the highest effective
// severity (the first one on ties) and that severity; -1 and Info when there
// is no detection.
func Strongest(dets []model.Detection) (int, model.Severity) {
	best, sev := -1, model.SevInfo
	for i, d := range dets {
		if s := dojo.DetectionSeverity(d); i == 0 || severityRank[s] > severityRank[sev] {
			best, sev = i, s
		}
	}
	return best, sev
}
