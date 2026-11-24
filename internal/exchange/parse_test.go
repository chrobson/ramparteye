package exchange

import (
	"bytes"
	"strings"
	"testing"

	"github.com/ctx42/testing/pkg/assert"
	"github.com/ctx42/testing/pkg/must"

	"github.com/chrobson/ramparteye/internal/model"
)

func TestDetectFormat(t *testing.T) {
	tests := map[string]Format{
		"<?xml version=\"1.0\"?>\n<nmaprun>": FormatNmapXML,
		"\xef\xbb\xbf  {\"findings\": []}":   FormatGeneric,
		"value,tags\n10.0.0.1,a":             FormatUnknown,
		"<html></html>":                      FormatUnknown,
		"":                                   FormatUnknown,
	}
	for in, want := range tests {
		assert.Equal(t, want, DetectFormat([]byte(in)), in)
	}
}

func TestParseNmapXML(t *testing.T) {
	f, obs, err := Parse(readFile(t, "nmap_sample.xml"))

	assert.NoError(t, err)
	assert.Equal(t, FormatNmapXML, f)
	assert.Len(t, 3, obs.Hosts)
	assert.Equal(t, "web.lab.test", obs.Hosts[0].Hostname)
	assert.False(t, obs.Hosts[2].Up)
	want := []model.ServiceObs{
		{Key: key("10.20.0.11", 22, "tcp"), Product: "OpenSSH", Version: "9.6p1", ExtraInfo: "protocol 2.0",
			CPE: "cpe:/a:openbsd:openssh:9.6p1", Banner: "ssh"},
		{Key: key("10.20.0.11", 443, "tcp"), Product: "nginx", Version: "1.27.4",
			CPE: "cpe:/a:f5:nginx:1.27.4", Banner: "ssl/http"},
		{Key: key("10.20.0.14", 53, "udp"), Product: "dnsmasq", Version: "2.90", Banner: "domain"},
		{Key: key("10.20.0.14", 80, "tcp"), Banner: "http"},
	}
	assert.Equal(t, want, obs.Services)
}

func TestParseNmapXMLTruncated(t *testing.T) {
	_, _, err := Parse([]byte(`<nmaprun><host>`))

	assert.Error(t, err)
}

func TestParseNmapXMLSanitisesHostText(t *testing.T) {
	long := strings.Repeat("A", 5000)
	x := `<nmaprun><host><status state="up"/><address addr="10.20.0.9" addrtype="ipv4"/>` +
		`<ports><port protocol="tcp" portid="80"><state state="open"/>` +
		`<service name="http" product="` + long + `"/></port></ports></host></nmaprun>`

	_, obs, err := Parse([]byte(x))

	assert.NoError(t, err)
	assert.Len(t, 1, obs.Services)
	assert.True(t, len(obs.Services[0].Product) <= 512)
}

func TestParseTooLarge(t *testing.T) {
	b := append([]byte("<nmaprun>"), bytes.Repeat([]byte(" "), MaxImportSize)...)

	_, _, err := Parse(b)

	assert.ErrorIs(t, ErrTooLarge, err)
}

func TestParseUnknownFormat(t *testing.T) {
	f, _, err := Parse([]byte("value,tags\n10.20.0.1,x\n"))

	assert.ErrorIs(t, ErrUnknownFormat, err)
	assert.Equal(t, FormatUnknown, f)
	assert.True(t, strings.Contains(err.Error(), "unknown import format"))
}

func TestParseGenericFindingsGolden(t *testing.T) {
	f, obs, err := Parse(readFile(t, "golden_findings.json"))

	assert.NoError(t, err)
	assert.Equal(t, FormatGeneric, f)
	assert.Len(t, 0, obs.Errors)
	assert.Len(t, 5, obs.Services)
	assert.Len(t, 4, obs.Hosts)

	svc := map[model.AssetKey]model.ServiceObs{}
	for _, s := range obs.Services {
		svc[s.Key] = s
	}
	ssh := svc[key("10.20.0.11", 22, "tcp")]
	assert.Equal(t, "OpenSSH", ssh.Product) // from steps_to_reproduce
	assert.Equal(t, "9.6p1", ssh.Version)
	assert.Equal(t, "protocol 2.0", ssh.ExtraInfo)
	_, ok := svc[key("10.20.0.30", 53, "udp")]
	assert.True(t, ok)

	dets := map[string]ImportedDetection{}
	for _, d := range obs.Detections {
		dets[d.SignatureID] = d
	}
	assert.Len(t, 3, dets)
	pma := dets["phpmyadmin"]
	assert.Equal(t, "admin-panel", pma.Category)
	assert.Equal(t, "phpMyAdmin", pma.Name)
	assert.Equal(t, key("10.20.0.14", 80, "tcp"), pma.Key)
	assert.Equal(t, 100, pma.Confidence)
	assert.Equal(t, "phpMyAdmin", pma.Evidence["title"])
	wp := dets["wordpress"]
	assert.Equal(t, "cms", wp.Category)
	assert.Equal(t, 90, wp.Confidence)
	assert.Equal(t, "WordPress 6.5", wp.Evidence["meta_generator"])
	assert.Equal(t, "import", wp.Evidence["source"])
	var host model.HostObs
	for _, h := range obs.Hosts {
		if h.IP == key("10.20.0.11", 0, "").IP {
			host = h
		}
	}
	assert.Equal(t, "web.lab.test", host.Hostname)
}

func TestParseGenericRejectsInvalid(t *testing.T) {
	_, _, err := Parse([]byte(`{"findings":[{"title":"t"}]}`))

	assert.Error(t, err)
}

func TestFromFindingsVHostAndForeign(t *testing.T) {
	fs := []model.Finding{
		{Title: "Open service 443/tcp", Severity: model.SevInfo, Description: "d",
			UniqueIDFromTool: "rampart:svc:10.20.0.11:443/tcp@shop.lab.test",
			Endpoints:        []model.AssetKey{{Port: 443, Proto: "tcp", VHost: "shop.lab.test"}}},
		{Title: "XSS", Severity: model.SevHigh, Description: "d", UniqueIDFromTool: "zap-1",
			Endpoints: []model.AssetKey{{Port: 443, Proto: "tcp", VHost: "example.test"}}},
		{Title: "no endpoints", Severity: model.SevInfo, Description: "d"},
	}

	obs := FromFindings(fs)

	assert.Len(t, 1, obs.Services)
	assert.Equal(t, model.AssetKey{IP: key("10.20.0.11", 0, "").IP, Port: 443, Proto: "tcp", VHost: "shop.lab.test"},
		obs.Services[0].Key)
	assert.Len(t, 2, obs.Errors)
}

func TestFromFindingsBoundsHostileText(t *testing.T) {
	evidence := "\nEvidence:\n\n- `k`: `" + strings.Repeat("x", 5000) + "`\n"
	fs := []model.Finding{{
		Title: "Technology detected: " + strings.Repeat("N", 5000), Severity: model.SevInfo, Description: "d",
		Observed:         "- Hostname: `" + strings.Repeat("h", 5000) + "`\n- Confidence: `900%`" + evidence + "\x00bad\xff",
		UniqueIDFromTool: "rampart:sig:10.20.0.5:80:x", VulnIDFromTool: "x",
		Endpoints: []model.AssetKey{key("10.20.0.5", 80, "tcp")},
	}}

	obs := FromFindings(fs)

	assert.Len(t, 1, obs.Detections)
	d := obs.Detections[0]
	assert.True(t, len(d.Name) <= 512)
	assert.True(t, len(d.Evidence["k"]) <= 256)
	assert.Equal(t, 100, d.Confidence)
	assert.True(t, len(obs.Hosts[0].Hostname) <= 512)
}

func TestExportImportRoundTrip(t *testing.T) {
	b := must.Value(snapshot().Dojo())

	f, obs, err := Parse(b)

	assert.NoError(t, err)
	assert.Equal(t, FormatGeneric, f)
	assert.Len(t, 2, obs.Services)
	assert.Len(t, 2, obs.Detections)
	var apache ImportedDetection
	for _, d := range obs.Detections {
		if d.SignatureID == "apache" {
			apache = d
		}
	}
	assert.Equal(t, 90, apache.Confidence)
	assert.Equal(t, "Apache", apache.Name)
}

func TestParseGenericIgnoresUnknownKeys(t *testing.T) {
	doc := `{"scan_type":"x","findings":[{"title":"Open 22","severity":"Info","description":"d",` +
		`"active":true,"verified":false,"false_p":false,"duplicate":false,"out_of_scope":false,` +
		`"risk_accepted":false,"unique_id_from_tool":"u1","endpoints":[{"host":"10.20.0.5","port":22,` +
		`"protocol":"tcp","extra":1}]}]}`

	f, obs, err := Parse([]byte(doc))

	assert.NoError(t, err)
	assert.Equal(t, FormatGeneric, f)
	assert.Len(t, 1, obs.Services)
	assert.Equal(t, []string{"ignored unsupported keys: active, duplicate, extra, false_p, out_of_scope, " +
		"risk_accepted, scan_type, verified"}, obs.Warnings)
}

func TestParseGenericStillFailsStructure(t *testing.T) {
	_, _, err := Parse([]byte(`{"findings":[{"title":"t","active":true}]}`))

	assert.Error(t, err)
}

func TestParseCapsErrors(t *testing.T) {
	var fs []model.Finding
	for range 250 {
		fs = append(fs, model.Finding{Title: "x", Severity: model.SevInfo, Description: "d"})
	}

	obs := FromFindings(fs)

	assert.Len(t, 100, obs.Errors)
	assert.Equal(t, 150, obs.ErrorsTruncated)
}

func TestParseTooManyEndpoints(t *testing.T) {
	var b strings.Builder
	b.WriteString(`{"findings":[{"title":"t","severity":"Info","description":"d","unique_id_from_tool":"u","endpoints":[`)
	for i := 0; i <= MaxItems; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(`{"host":"10.0.0.1","port":80}`)
	}
	b.WriteString(`]}]}`)

	_, _, err := Parse([]byte(b.String()))

	assert.ErrorIs(t, ErrTooManyItems, err)
}
