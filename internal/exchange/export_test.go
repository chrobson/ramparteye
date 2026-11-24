package exchange

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"net/netip"
	"testing"
	"time"

	"github.com/ctx42/testing/pkg/assert"
	"github.com/ctx42/testing/pkg/must"

	"github.com/chrobson/ramparteye/internal/dojo"
	"github.com/chrobson/ramparteye/internal/model"
)

func snapshot() Snapshot {
	return Snapshot{
		RunID: 7, RunKind: "scan", Date: time.Date(2026, 11, 21, 18, 0, 0, 0, time.UTC),
		Services: []dojo.Service{
			{ServiceObs: model.ServiceObs{Key: key("10.20.0.14", 80, "tcp"), Product: "Apache httpd"},
				HTTP: &dojo.HTTPSummary{URL: "http://10.20.0.14/", Status: 200, Title: "=cmd|' /C calc'!A0"},
				Detections: []model.Detection{
					{SignatureID: "phpmyadmin", Name: "phpMyAdmin", Category: "admin-panel", Confidence: 100},
					{SignatureID: "apache", Name: "Apache", Category: "server", Confidence: 90},
				}},
			{ServiceObs: model.ServiceObs{Key: key("10.20.0.11", 22, "tcp"), Product: "OpenSSH", Version: "9.6p1"},
				Hostname: "web.lab.test"},
		},
		Annotations: []dojo.Annotation{
			{Key: key("10.20.0.11", 22, "tcp"), Severity: "Low", Tags: []string{"ops"}, Comment: "old"},
			{Key: model.AssetKey{IP: netip.MustParseAddr("10.20.0.11")}, Tags: []string{"dmz"}},
		},
	}
}

func readCSV(t *testing.T, s Snapshot) [][]string {
	t.Helper()
	var buf bytes.Buffer
	assert.NoError(t, WriteCSV(&buf, s))
	return must.Value(csv.NewReader(&buf).ReadAll())
}

func col(t *testing.T, row []string, name string) string {
	t.Helper()
	for i, h := range CSVHeader {
		if h == name {
			return row[i]
		}
	}
	t.Fatalf("no column %s", name)
	return ""
}

func TestWriteCSV(t *testing.T) {
	rows := readCSV(t, snapshot())

	assert.Equal(t, CSVHeader, rows[0])
	assert.Len(t, 3, rows)
	ssh, web := rows[1], rows[2] // sorted by IP
	assert.Equal(t, "10.20.0.11", col(t, ssh, "ip"))
	assert.Equal(t, "Low", col(t, ssh, "severity"))
	assert.Equal(t, "dmz;ops", col(t, ssh, "tags"))
	assert.Equal(t, "web.lab.test", col(t, ssh, "hostname"))
	assert.Equal(t, "apache;phpmyadmin", col(t, web, "detections"))
	assert.Equal(t, "admin-panel;server", col(t, web, "categories"))
}

func TestCSVHeaderEnglish(t *testing.T) {
	want := []string{"ip", "hostname", "port", "proto", "vhost", "product", "version", "extrainfo", "cpe",
		"url", "http_status", "http_title", "detections", "categories",
		"severity", "false_positive", "tags", "comment"}

	assert.Equal(t, want, CSVHeader)
}

func TestCSVFormulaInjectionEscaped(t *testing.T) {
	rows := readCSV(t, snapshot())

	assert.Equal(t, "'=cmd|' /C calc'!A0", col(t, rows[2], "http_title"))
}

func TestSafeCell(t *testing.T) {
	for _, in := range []string{"=1", "+1", "-1", "@SUM", "\tx", "\rx"} {
		assert.Equal(t, "'"+in, safeCell(in), in)
	}
	for _, in := range []string{"", "plain", "a=b", "'=x"} {
		assert.Equal(t, in, safeCell(in), in)
	}
	assert.Equal(t, "a�b", safeCell("a\xffb"))
}

func TestCSVEscapesEveryColumn(t *testing.T) {
	s := snapshot()
	s.Services[0].Product = "@evil"
	s.Services[0].Hostname = "+evil"
	s.Annotations = []dojo.Annotation{{Key: s.Services[0].Key, Comment: "-evil", Tags: []string{"=t"}}}

	rows := readCSV(t, s)

	web := rows[2]
	assert.Equal(t, "'@evil", col(t, web, "product"))
	assert.Equal(t, "'+evil", col(t, web, "hostname"))
	assert.Equal(t, "'-evil", col(t, web, "comment"))
	assert.Equal(t, "'=t", col(t, web, "tags"))
}

func TestWriteJSON(t *testing.T) {
	var buf bytes.Buffer
	assert.NoError(t, WriteJSON(&buf, snapshot()))

	var doc Document
	assert.NoError(t, json.Unmarshal(buf.Bytes(), &doc))
	assert.Equal(t, int64(7), doc.RunID)
	assert.Len(t, 2, doc.Services)
	assert.Equal(t, "10.20.0.14", doc.Services[1].IP)
	assert.Len(t, 2, doc.Services[1].Detections)
	assert.Equal(t, "apache", doc.Services[1].Detections[0].SignatureID)
	a := doc.Services[0].Annotation
	assert.NotNil(t, a)
	assert.Equal(t, "Low", a.Severity)
	assert.False(t, a.FalsePositive)
	assert.NotNil(t, doc.Services[0].Detections) // [] not null
}

func TestSnapshotDojoValid(t *testing.T) {
	b, err := snapshot().Dojo()

	assert.NoError(t, err)
	assert.NoError(t, dojo.Validate(b))
}
