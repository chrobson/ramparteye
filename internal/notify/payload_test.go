package notify

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/ctx42/testing/pkg/assert"
	"github.com/ctx42/testing/pkg/must"

	"github.com/chrobson/ramparteye/internal/model"
	"github.com/chrobson/ramparteye/internal/safety"
	"github.com/chrobson/ramparteye/internal/store"
)

var (
	t0      = time.Date(2026, 11, 24, 10, 0, 0, 0, time.UTC)
	t1      = t0.Add(12 * time.Minute)
	sentAt  = time.Date(2026, 11, 24, 10, 15, 0, 0, time.UTC)
	instID  = "0123456789abcdef01234567"
	baseURL = "https://rampart.example"
)

func akey(ip string, port uint16) model.AssetKey {
	return model.AssetKey{IP: netip.MustParseAddr(ip), Port: port, Proto: "tcp"}
}

func svc(ip string, port uint16, banner, product, version string, dets ...model.Detection) store.ExportService {
	return store.ExportService{ServiceObs: model.ServiceObs{Key: akey(ip, port), Banner: banner, Product: product,
		Version: version}, Detections: dets}
}

// sampleRun is a finished run with two new services, one changed, one
// gone, a host gone and an unchanged database.
func sampleRun() *runData {
	tomcat := svc("10.20.0.5", 8080, "http", "Apache Tomcat", "9.0.1",
		model.Detection{SignatureID: "tomcat-manager", Name: "Tomcat Manager", Category: "admin-panel", Confidence: 100})
	tomcat.Hostname = "intranet"
	ssh := svc("10.20.0.6", 22, "ssh", "OpenSSH", "9.6")
	nginx := svc("10.20.0.7", 443, "https", "nginx", "1.27")
	redis := svc("10.20.0.8", 6379, "redis", "Redis", "7.2")
	return &runData{
		Run: store.RunSummary{ID: 42, ConfigName: "Campus", Kind: "scan", Status: store.RunDone, StartedAt: &t0,
			FinishedAt: &t1, HostsUp: 4, Services: 4},
		PrevRunID: 41,
		Changes: []model.Change{
			{Kind: model.ChangeNew, Key: ssh.Key},
			{Kind: model.ChangeNew, Key: tomcat.Key},
			{Kind: model.ChangeChanged, Key: nginx.Key, Field: "version", Old: "1.26", New: "1.27"},
			{Kind: model.ChangeGone, Key: akey("10.20.0.9", 21)},
			{Kind: model.ChangeHostDown, Key: akey("10.20.0.9", 0)},
		},
		Services: []store.ExportService{ssh, tomcat, nginx, redis},
		Safety:   &safety.Report{Status: safety.ReportOK},
	}
}

func decode(t *testing.T, b []byte) map[string]any {
	t.Helper()
	var m map[string]any
	must.Nil(json.Unmarshal(b, &m))
	return m
}

func TestBuildFinishedJSON(t *testing.T) {
	m := buildMessage(EventFinished, sentAt, instID, baseURL, sampleRun())

	body := must.Value(m.JSON())

	got := decode(t, body)
	assert.Equal(t, 1.0, got["version"])
	assert.Equal(t, "scan.finished", got["event"])
	assert.Equal(t, instID, got["instance"])
	assert.Equal(t, "2026-11-24T10:15:00Z", got["sent_at"])
	run := got["run"].(map[string]any)
	assert.Equal(t, 42.0, run["id"])
	assert.Equal(t, "Campus", run["profile"])
	assert.Equal(t, "done", run["status"])
	assert.Equal(t, "2026-11-24T10:00:00Z", run["started_at"])
	assert.Equal(t, "2026-11-24T10:12:00Z", run["finished_at"])
	assert.Equal(t, 4.0, run["hosts_up"])
	assert.Equal(t, 4.0, run["services"])
	assert.Equal(t, 41.0, run["previous_run"])
	assert.Equal(t, map[string]any{"new": 2.0, "gone": 1.0, "changed": 1.0, "host_up": 0.0, "host_down": 1.0,
		"unstable": 0.0, "total": 5.0}, got["changes"])
	assert.Equal(t, "Since the last scan: 2 new exposures, 1 host gone, 1 service changed.", got["headline"])
	assert.Equal(t, "1 service needs attention first.", got["attention"])
	assert.Equal(t, map[string]any{"status": "ok", "not_passed": []any{}}, got["safety"])
	assert.Equal(t, map[string]any{"run": "https://rampart.example/scans/42",
		"changes": "https://rampart.example/changes/42"}, got["links"])

	// New and changed services only, highest interest score first.
	top := got["top"].([]any)
	assert.Equal(t, 3.0, got["top_total"])
	assert.Len(t, 3, top)
	first := top[0].(map[string]any)
	assert.Equal(t, map[string]any{"change": "new", "address": "10.20.0.5", "port": 8080.0, "protocol": "tcp",
		"hostname": "intranet", "product": "Apache Tomcat", "version": "9.0.1", "severity": "Medium",
		"score": 60.0, "detections": []any{"Tomcat Manager"}}, first)
	assert.Equal(t, "10.20.0.6", top[1].(map[string]any)["address"])
	assert.Equal(t, "changed", top[2].(map[string]any)["change"])
	_, hasSev := top[1].(map[string]any)["severity"]
	assert.False(t, hasSev) // no detection, no severity
}

func TestBuildWithoutBaseURLHasNoLinks(t *testing.T) {
	m := buildMessage(EventFinished, sentAt, instID, "", sampleRun())

	got := decode(t, must.Value(m.JSON()))

	_, ok := got["links"]
	assert.False(t, ok)
	assert.NotContain(t, "http", string(must.Value(m.Slack())))
}

func TestBuildTopIsLimited(t *testing.T) {
	d := sampleRun()
	d.Changes, d.Services = nil, nil
	for i := range 25 {
		s := svc(fmt.Sprintf("10.20.1.%d", i+1), 80, "http", "", "")
		d.Services = append(d.Services, s)
		d.Changes = append(d.Changes, model.Change{Kind: model.ChangeNew, Key: s.Key})
	}

	m := buildMessage(EventFinished, sentAt, instID, "", d)

	assert.Len(t, maxTop, m.Top)
	assert.Equal(t, 25, m.TopTotal)
	assert.Contain(t, "and 15 more", string(must.Value(m.Slack())))
}

func TestBuildFailedRun(t *testing.T) {
	d := sampleRun()
	d.Run.Status, d.Run.ChunksFailed, d.Run.ChunksTotal = store.RunFailed, 2, 8
	d.Changes, d.PrevRunID = nil, 0
	d.Safety = &safety.Report{Status: safety.ReportIncomplete, Checks: []safety.Check{
		{Name: "scope respected", Status: safety.StatusPass, OK: true},
		{Name: "rate within budget", Status: safety.StatusUnmeasured}}}

	m := buildMessage(EventFailed, sentAt, instID, baseURL, d)
	got := decode(t, must.Value(m.JSON()))

	assert.Equal(t, "scan.failed", got["event"])
	assert.Equal(t, "Scan #42 failed.", got["headline"])
	assert.Equal(t, "2 of 8 chunks failed.", got["attention"])
	assert.Nil(t, got["run"].(map[string]any)["previous_run"])
	assert.Equal(t, map[string]any{"status": "incomplete", "not_passed": []any{"rate within budget"}}, got["safety"])
	assert.Equal(t, map[string]any{"run": "https://rampart.example/scans/42"}, got["links"])
	assert.Equal(t, []any{}, got["top"])
}

func TestBuildMissingReceipt(t *testing.T) {
	d := sampleRun()
	d.Safety = nil

	m := buildMessage(EventFinished, sentAt, instID, "", d)

	assert.Equal(t, "missing", m.Safety.Status)
}

func TestBuildTestEvent(t *testing.T) {
	m := buildMessage(EventTest, sentAt, instID, baseURL, nil)
	got := decode(t, must.Value(m.JSON()))
	assert.Equal(t, "test", got["event"])
	assert.Nil(t, got["run"])
	assert.Contain(t, "Test notification", got["headline"].(string))
	assert.Contain(t, "[TEST]", string(must.Value(m.Slack())))

	// With a finished run the test shows what a real message looks like.
	m = buildMessage(EventTest, sentAt, instID, baseURL, sampleRun())
	got = decode(t, must.Value(m.JSON()))
	assert.Equal(t, "test", got["event"])
	assert.Equal(t, 42.0, got["run"].(map[string]any)["id"])
	assert.Equal(t, "Test notification. Since the last scan: 2 new exposures, 1 host gone, 1 service changed.",
		got["headline"])
}

// hostile is scanned content trying to break out of the message.
const hostile = "<!channel> <https://evil.example|click> *bold* `code` @here &amp; \x1b[31m‮evil\r\nline2\x00"

func hostileRun() *runData {
	d := sampleRun()
	s := svc("10.20.0.66", 8443, hostile, hostile+strings.Repeat("P", 500), hostile+strings.Repeat("V", 500),
		model.Detection{SignatureID: "custom", Name: hostile + strings.Repeat("D", 500), Category: "admin-panel",
			Confidence: 100, Evidence: map[string]string{"severity": "high"}},
		model.Detection{SignatureID: "c2", Name: "b"}, model.Detection{SignatureID: "c3", Name: "c"},
		model.Detection{SignatureID: "c4", Name: "d"}, model.Detection{SignatureID: "c5", Name: "e"},
		model.Detection{SignatureID: "c6", Name: "f"}, model.Detection{SignatureID: "c7", Name: "g"})
	s.Hostname = hostile + strings.Repeat("h", 500)
	d.Run.ConfigName = "Profile <!here>"
	d.Services = append(d.Services, s)
	d.Changes = append(d.Changes, model.Change{Kind: model.ChangeNew, Key: s.Key})
	return d
}

func TestScannedContentIsSanitisedInJSON(t *testing.T) {
	m := buildMessage(EventFinished, sentAt, instID, "", hostileRun())

	it := m.Top[0]
	assert.Equal(t, "10.20.0.66", it.Address)
	for _, v := range append([]string{it.Product, it.Version, it.Hostname}, it.Detections...) {
		assert.True(t, utf8.ValidString(v))
		assert.False(t, strings.ContainsAny(v, "\x00\x1b\r\n‮"), v)
	}
	assert.True(t, utf8.RuneCountInString(it.Product) <= maxProduct, it.Product)
	assert.True(t, utf8.RuneCountInString(it.Version) <= maxVersion, it.Version)
	assert.True(t, utf8.RuneCountInString(it.Hostname) <= maxHostname, it.Hostname)
	assert.True(t, utf8.RuneCountInString(it.Detections[0]) <= maxDetection, it.Detections[0])
	assert.Len(t, maxDetections, it.Detections)
	assert.True(t, strings.HasSuffix(it.Product, "…"))
}

func TestScannedContentCannotInjectIntoSlack(t *testing.T) {
	m := buildMessage(EventFinished, sentAt, instID, baseURL, hostileRun())

	var p struct {
		Text string `json:"text"`
	}
	body := must.Value(m.Slack())
	must.Nil(json.Unmarshal(body, &p))
	text := p.Text

	// No mention, link or control sequence from scanned content survives.
	assert.NotContain(t, "<!channel>", text)
	assert.NotContain(t, "<!here>", text)
	assert.NotContain(t, "<https://evil", text)
	assert.Contain(t, "&lt;!channel&gt;", text)
	assert.False(t, strings.ContainsAny(text, "\x00\x1b\r‮"), text)
	// The only links are the ones built from the base URL.
	assert.Equal(t, 2, strings.Count(text, "<"))
	assert.Contain(t, "<https://rampart.example/scans/42|Run #42>", text)
	assert.Contain(t, "<https://rampart.example/changes/42|Changes>", text)
	// Scanned values are code spans; their own backticks cannot close them.
	for _, line := range strings.Split(text, "\n") {
		assert.Equal(t, 0, strings.Count(line, "`")%2, line)
	}
	assert.Contain(t, "`Profile &lt;!here&gt;`", text)
	assert.True(t, len(text) <= maxSlackText)
}

func TestSlackMessageIsCapped(t *testing.T) {
	d := hostileRun()
	for i := range 40 {
		s := hostileRun().Services[4]
		s.Key = akey(fmt.Sprintf("10.20.2.%d", i+1), 443)
		d.Services = append(d.Services, s)
		d.Changes = append(d.Changes, model.Change{Kind: model.ChangeNew, Key: s.Key})
	}
	m := buildMessage(EventFinished, sentAt, instID, baseURL, d)

	text := m.slackText(1500)

	assert.True(t, len(text) <= 1500, fmt.Sprint(len(text)))
	assert.Contain(t, "more", text)
	assert.Contain(t, "<https://rampart.example/scans/42|Run #42>", text) // links kept
	for _, line := range strings.Split(text, "\n") {
		assert.Equal(t, 0, strings.Count(line, "`")%2, line)
	}
}

func TestJSONIsCapped(t *testing.T) {
	m := buildMessage(EventFinished, sentAt, instID, baseURL, hostileRun())
	full := must.Value(m.JSON())

	body := must.Value(m.jsonLimit(len(full) - 1))

	assert.True(t, len(body) < len(full))
	got := decode(t, body)
	assert.Len(t, len(m.Top)-1, got["top"].([]any))
	assert.Equal(t, float64(m.TopTotal), got["top_total"])
}

func TestClean(t *testing.T) {
	assert.Equal(t, "a b c", clean(" a\tb\n\nc\x00 ", 10))
	assert.Equal(t, "abcd…", clean("abcdefgh", 5))
	assert.Equal(t, "żółw", clean("żółw", 4))
	assert.Equal(t, "evil", clean("‮ev​il", 10))
	assert.Equal(t, "x", clean("x\xff", 10))
	assert.Equal(t, "", clean("\x01\x02", 10))
}
