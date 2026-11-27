package notify

import (
	"encoding/json"
	"net/netip"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/chrobson/ramparteye/internal/model"
	"github.com/chrobson/ramparteye/internal/safety"
	"github.com/chrobson/ramparteye/internal/store"
	"github.com/chrobson/ramparteye/internal/summary"
)

// Events of a message.
const (
	EventFinished = "scan.finished"
	EventFailed   = "scan.failed"
	EventTest     = "test"
)

// PayloadVersion is the version of the JSON message; it changes only when
// a field is removed or changes meaning.
const PayloadVersion = 1

// Limits of a message. Everything from scanned hosts is cut to a length
// (in runes) and the whole body to a size.
const (
	maxTop        = 10
	maxProfile    = 100
	maxProduct    = 100
	maxVersion    = 60
	maxHostname   = 120
	maxDetection  = 100
	maxDetections = 5
	maxJSONBody   = 64 << 10
	// maxSlackText stays below the post limits of Slack (40,000
	// characters) and Mattermost (16,383).
	maxSlackText = 12000
)

// Message is the JSON body of a notification (format "json", version 1)
// and the source of the Slack text. See docs/NOTIFICATIONS.md.
type Message struct {
	Version   int       `json:"version"`
	Event     string    `json:"event"`
	Instance  string    `json:"instance"`
	SentAt    time.Time `json:"sent_at"`
	Run       *Run      `json:"run"`
	Changes   Counts    `json:"changes"`
	Headline  string    `json:"headline"`
	Attention string    `json:"attention"`
	Top       []Item    `json:"top"`
	// TopTotal is the number of new and changed services; Top holds the
	// first maxTop of them.
	TopTotal int    `json:"top_total"`
	Safety   Safety `json:"safety"`
	Links    *Links `json:"links,omitempty"`
}

// Run is the run a message is about.
type Run struct {
	ID          int64      `json:"id"`
	Profile     string     `json:"profile"`
	Status      string     `json:"status"`
	StartedAt   *time.Time `json:"started_at"`
	FinishedAt  *time.Time `json:"finished_at"`
	HostsUp     int        `json:"hosts_up"`
	Services    int        `json:"services"`
	PreviousRun *int64     `json:"previous_run"`
}

// Counts are the changes of the run by kind.
type Counts struct {
	New      int `json:"new"`
	Gone     int `json:"gone"`
	Changed  int `json:"changed"`
	HostUp   int `json:"host_up"`
	HostDown int `json:"host_down"`
	Unstable int `json:"unstable"`
	Total    int `json:"total"`
}

// Item is a new or changed service worth looking at.
type Item struct {
	Change     string   `json:"change"` // new | changed
	Address    string   `json:"address"`
	Port       int      `json:"port"`
	Protocol   string   `json:"protocol"`
	Hostname   string   `json:"hostname,omitempty"`
	Product    string   `json:"product"`
	Version    string   `json:"version"`
	Severity   string   `json:"severity,omitempty"` // highest detection severity
	Score      int      `json:"score"`              // interest score, 0-100
	Detections []string `json:"detections"`
}

// Safety is the safety receipt verdict of the run: ok, incomplete, failed,
// or missing when no receipt was stored. NotPassed names the checks that
// failed or could not be measured.
type Safety struct {
	Status    string   `json:"status"`
	NotPassed []string `json:"not_passed"`
}

// Links point to this instance when a public base URL is configured.
type Links struct {
	Run     string `json:"run"`
	Changes string `json:"changes,omitempty"`
}

// runData is the stored result of a run a message is built from.
type runData struct {
	Run       store.RunSummary
	PrevRunID int64
	Changes   []model.Change
	Services  []store.ExportService
	Unstable  map[netip.Addr]bool
	Notes     map[model.AssetKey]store.Annotation
	Safety    *safety.Report // nil = no receipt
}

// buildMessage builds the message of event about d (nil: a test without a
// finished run). baseURL ("" = none) must be normalised.
func buildMessage(event string, now time.Time, instance, baseURL string, d *runData) Message {
	// Whole seconds, so sent_at equals the X-Rampart-Timestamp header.
	m := Message{Version: PayloadVersion, Event: event, Instance: instance, SentAt: now.UTC().Truncate(time.Second),
		Top:    []Item{},
		Safety: Safety{Status: "missing", NotPassed: []string{}}}
	if d == nil {
		m.Headline = "Test notification from RampartEye."
		m.Attention = "No scan has finished yet; real notifications describe the changes of each scan."
		return m
	}
	r := d.Run
	m.Run = &Run{ID: r.ID, Profile: clean(r.ConfigName, maxProfile), Status: r.Status, StartedAt: utc(r.StartedAt),
		FinishedAt: utc(r.FinishedAt), HostsUp: r.HostsUp, Services: r.Services}
	if d.PrevRunID != 0 {
		prev := d.PrevRunID
		m.Run.PreviousRun = &prev
	}
	c := summary.CountChanges(d.Changes)
	m.Changes = Counts{New: c.NewServices, Gone: c.ServicesGone, Changed: c.Changed, HostUp: c.NewHosts,
		HostDown: c.HostsGone, Unstable: c.Unstable, Total: c.Total()}
	if d.Safety != nil {
		m.Safety.Status = string(d.Safety.Status)
		for _, ch := range d.Safety.Checks {
			if !ch.OK {
				m.Safety.NotPassed = append(m.Safety.NotPassed, ch.Name)
			}
		}
	}
	urgent := 0
	for _, rk := range summary.Rank(d.Services, summary.ChangeKinds(d.Changes), d.Unstable, d.Notes) {
		if rk.Score >= summary.UrgentMin {
			urgent++
		}
		change := changeOf(rk.Kinds)
		if change == "" {
			continue
		}
		m.TopTotal++
		if len(m.Top) < maxTop {
			m.Top = append(m.Top, item(rk, change))
		}
	}
	if r.Status == store.RunFailed {
		m.Headline = "Scan #" + strconv.FormatInt(r.ID, 10) + " failed."
		m.Attention = strconv.Itoa(r.ChunksFailed) + " of " + strconv.Itoa(r.ChunksTotal) + " chunks failed."
	} else {
		m.Headline, m.Attention = summary.Headline(c, urgent)
	}
	if event == EventTest {
		m.Headline = "Test notification. " + m.Headline
	}
	if baseURL != "" {
		id := strconv.FormatInt(r.ID, 10)
		m.Links = &Links{Run: baseURL + "/scans/" + id}
		if r.Status == store.RunDone {
			m.Links.Changes = baseURL + "/changes/" + id
		}
	}
	return m
}

// changeOf returns the change kind that makes a service a top item.
func changeOf(kinds []string) string {
	for _, k := range kinds {
		if k == string(model.ChangeNew) || k == string(model.ChangeChanged) {
			return k
		}
	}
	return ""
}

func item(rk summary.Ranked, change string) Item {
	sv := rk.Service
	it := Item{Change: change, Address: sv.Key.IP.Unmap().String(), Port: int(sv.Key.Port),
		Protocol: clean(sv.Key.Proto, 8), Hostname: clean(sv.Hostname, maxHostname),
		Product: clean(sv.Product, maxProduct), Version: clean(sv.Version, maxVersion), Score: rk.Score,
		Detections: []string{}}
	if i, sev := summary.Strongest(sv.Detections); i >= 0 {
		it.Severity = string(sev)
	}
	for _, d := range sv.Detections {
		if len(it.Detections) == maxDetections {
			break
		}
		if name := clean(d.Name, maxDetection); name != "" {
			it.Detections = append(it.Detections, name)
		}
	}
	return it
}

func utc(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	u := t.UTC()
	return &u
}

// JSON returns the "json" body, at most maxJSONBody bytes.
func (m Message) JSON() ([]byte, error) { return m.jsonLimit(maxJSONBody) }

// jsonLimit marshals m, dropping top items from the end until the body
// fits limit (TopTotal still counts them).
func (m Message) jsonLimit(limit int) ([]byte, error) {
	for {
		b, err := json.Marshal(m)
		if err != nil || len(b) <= limit || len(m.Top) == 0 {
			return b, err
		}
		m.Top = m.Top[:len(m.Top)-1]
	}
}

// Slack returns the "slack" body: {"text": ...} in Slack mrkdwn, which
// Mattermost and Rocket.Chat accept on their Slack-compatible webhooks.
func (m Message) Slack() ([]byte, error) {
	return json.Marshal(struct {
		Text string `json:"text"`
	}{m.slackText(maxSlackText)})
}

// slackText renders m in at most limit bytes. Every value that is not
// RampartEye's own text is escaped and set in a code span, so scanned
// content cannot add links, mentions (<!channel>, @here) or formatting;
// top items are dropped from the end when the text is too long.
func (m Message) slackText(limit int) string {
	var head []string
	switch {
	case m.Event == EventTest:
		head = append(head, "*[TEST] RampartEye test notification*")
	case m.Run != nil:
		verb := "finished"
		if m.Event == EventFailed {
			verb = "failed"
		}
		head = append(head, "*RampartEye*: scan #"+strconv.FormatInt(m.Run.ID, 10)+" "+code(m.Run.Profile, "")+" "+verb)
	}
	head = append(head, "*"+slackEscape(m.Headline)+"*", slackEscape(m.Attention))
	if m.Run != nil {
		c := m.Changes
		head = append(head, "Changes: "+strconv.Itoa(c.New)+" new · "+strconv.Itoa(c.Gone)+" gone · "+
			strconv.Itoa(c.Changed)+" changed · "+summary.Plural(c.HostUp, "host", "hosts")+" up · "+
			summary.Plural(c.HostDown, "host", "hosts")+" down · "+strconv.Itoa(c.Unstable)+" unstable",
			"Safety receipt: "+slackEscape(m.Safety.Status))
	}
	var tail []string
	if m.Links != nil {
		id := strconv.FormatInt(m.Run.ID, 10)
		l := slackLink(m.Links.Run, "Run #"+id)
		if m.Links.Changes != "" {
			l += " · " + slackLink(m.Links.Changes, "Changes")
		}
		tail = append(tail, l)
	}
	items := make([]string, len(m.Top))
	for i, it := range m.Top {
		items[i] = slackItem(it)
	}
	for n := len(items); ; n-- {
		lines := append([]string(nil), head...)
		if n > 0 {
			lines = append(lines, "*Top new and changed services:*")
			lines = append(lines, items[:n]...)
		}
		if more := m.TopTotal - n; more > 0 {
			lines = append(lines, "…and "+strconv.Itoa(more)+" more")
		}
		lines = append(lines, tail...)
		text := strings.Join(lines, "\n")
		if len(text) <= limit {
			return text
		}
		if n == 0 {
			return cutLines(text, limit)
		}
	}
}

func slackItem(it Item) string {
	ep := netip.AddrPortFrom(netip.MustParseAddr(it.Address), uint16(it.Port)).String() + "/" + it.Protocol
	parts := []string{"• " + code(ep, "")}
	if it.Hostname != "" {
		parts[0] += " " + code(it.Hostname, "")
	}
	parts = append(parts, it.Change)
	if p := strings.TrimSpace(it.Product + " " + it.Version); p != "" {
		parts = append(parts, code(p, ""))
	}
	if it.Severity != "" {
		parts = append(parts, it.Severity)
	}
	if len(it.Detections) > 0 {
		names := make([]string, len(it.Detections))
		for i, d := range it.Detections {
			names[i] = code(d, "")
		}
		parts = append(parts, strings.Join(names, ", "))
	}
	parts = append(parts, "score "+strconv.Itoa(it.Score))
	return strings.Join(parts, " · ")
}

// cutLines cuts text to at most limit bytes at a line end.
func cutLines(text string, limit int) string {
	for len(text) > limit {
		i := strings.LastIndexByte(text, '\n')
		if i < 0 {
			return ""
		}
		text = text[:i]
	}
	return text
}

// slackEscape escapes the three characters Slack mrkdwn treats as markup
// for links and mentions.
func slackEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}

// code sets s (already cleaned) in an escaped code span, so its content is
// shown literally; a backtick in s, which would end the span, becomes '.
// An empty s gives empty.
func code(s, empty string) string {
	if s == "" {
		return empty
	}
	return "`" + slackEscape(strings.ReplaceAll(s, "`", "'")) + "`"
}

// slackLink is a mrkdwn link to one of this instance's pages; url is built
// from the normalised base URL, text is RampartEye's own.
func slackLink(url, text string) string {
	return "<" + slackEscape(strings.NewReplacer("|", "%7C", " ", "%20").Replace(url)) + "|" + text + ">"
}

// clean makes a value from a scanned host safe to forward: invalid UTF-8,
// control and format characters (bidi overrides, zero-width) are dropped,
// whitespace runs become one space, and the result is cut to max runes
// (with "…").
func clean(s string, max int) string {
	s = strings.ToValidUTF8(s, "")
	var b strings.Builder
	space := false
	for _, r := range s {
		switch {
		case unicode.IsSpace(r):
			space = true
			continue
		case unicode.IsControl(r), unicode.Is(unicode.Cf, r):
			continue
		}
		if space && b.Len() > 0 {
			b.WriteByte(' ')
		}
		space = false
		b.WriteRune(r)
	}
	out := b.String()
	if utf8.RuneCountInString(out) <= max {
		return out
	}
	r := []rune(out)
	return strings.TrimSpace(string(r[:max-1])) + "…"
}
