package web

import (
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strings"

	"github.com/chrobson/ramparteye/internal/dojo"
	"github.com/chrobson/ramparteye/internal/model"
)

// findingsLimit bounds the rows on the findings page.
const findingsLimit = 1000

// Sort keys and directions of the findings page.
const (
	sortSeverity = "severity"
	sortScore    = "score"
	dirDesc      = "desc"
	dirAsc       = "asc"
)

// FindingItem is one detection of the latest finished run.
type FindingItem struct {
	Name        string
	SignatureID string
	Category    string
	Severity    model.Severity
	Score       int
	Confidence  int
	Endpoint    string
	VHost       string
	Href        string
	ip          netip.Addr
	port        uint16
}

// SortLink is a sortable column header.
type SortLink struct {
	Href    string
	Active  bool
	AriaDir string // ascending | descending (active column only)
	Arrow   string
}

// FindingsData is the findings page.
type FindingsData struct {
	Title    string
	Rows     []FindingItem
	Total    int
	Limit    int
	HasRun   bool
	Sort     string
	Dir      string
	Severity SortLink
	ScoreCol SortLink
}

// parseFindingsSort validates ?sort= and ?dir= (defaults severity, desc).
func parseFindingsSort(q url.Values) (sortKey, dir string, ok bool) {
	sortKey, dir = q.Get("sort"), q.Get("dir")
	if sortKey == "" {
		sortKey = sortSeverity
	}
	if dir == "" {
		dir = dirDesc
	}
	return sortKey, dir, (sortKey == sortSeverity || sortKey == sortScore) && (dir == dirDesc || dir == dirAsc)
}

func sortLink(col, cur, dir string) SortLink {
	href := func(d string) string { return "/findings?sort=" + col + "&dir=" + d } // constants only
	l := SortLink{Href: href(dirDesc)}
	if col == cur {
		l.Active = true
		l.AriaDir, l.Arrow = "descending", "↓"
		if dir == dirAsc {
			l.AriaDir, l.Arrow = "ascending", "↑"
		} else {
			l.Href = href(dirAsc)
		}
	}
	return l
}

func (s *Server) findingsPage(w http.ResponseWriter, r *http.Request) {
	sortKey, dir, ok := parseFindingsSort(r.URL.Query())
	if !ok {
		s.renderError(w, r, errorData{Code: http.StatusBadRequest, Title: "Invalid sort order",
			Text: "Findings can be sorted by severity or score, ascending or descending."})
		return
	}
	snap, err := s.loadSnapshot(r.Context())
	if err != nil {
		s.log.Error("load findings", "err", err)
		s.serverError(w, r)
		return
	}
	d := FindingsData{Title: "Findings", HasRun: snap.RunID != 0, Sort: sortKey, Dir: dir, Limit: findingsLimit,
		Severity: sortLink(sortSeverity, sortKey, dir), ScoreCol: sortLink(sortScore, sortKey, dir)}
	for _, svcs := range snap.Services {
		for _, sv := range svcs {
			for _, det := range sv.Detections {
				d.Rows = append(d.Rows, FindingItem{Name: det.Name, SignatureID: det.SignatureID,
					Category: strings.ReplaceAll(det.Category, "-", " "), Severity: dojo.DetectionSeverity(det),
					Score: sv.Result.Score, Confidence: det.Confidence, Endpoint: endpoint(sv.Key),
					VHost: sv.Key.VHost, Href: assetPath(sv.Key), ip: sv.Key.IP.Unmap(), port: sv.Key.Port})
			}
		}
	}
	sortFindings(d.Rows, sortKey, dir == dirAsc)
	d.Total = len(d.Rows)
	if len(d.Rows) > findingsLimit {
		d.Rows = d.Rows[:findingsLimit]
	}
	s.render(w, r, "findings", d)
}

// sortFindings orders by the key (ties: the other key, then address,
// port and name, always in a fixed order).
func sortFindings(rows []FindingItem, key string, asc bool) {
	sort.SliceStable(rows, func(i, j int) bool {
		a, b := rows[i], rows[j]
		sa, sb := severityRank[a.Severity], severityRank[b.Severity]
		first, second := [2]int{sa, a.Score}, [2]int{sb, b.Score}
		if key == sortScore {
			first, second = [2]int{a.Score, sa}, [2]int{b.Score, sb}
		}
		for k := range 2 {
			if first[k] != second[k] {
				return (first[k] < second[k]) == asc
			}
		}
		if a.ip != b.ip {
			return a.ip.Less(b.ip)
		}
		if a.port != b.port {
			return a.port < b.port
		}
		return a.Name < b.Name
	})
}
