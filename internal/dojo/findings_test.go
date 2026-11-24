package dojo

import (
	"bytes"
	"flag"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ctx42/testing/pkg/assert"
	"github.com/ctx42/testing/pkg/must"

	"github.com/chrobson/ramparteye/internal/model"
)

var update = flag.Bool("update", false, "rewrite golden files in testdata")

const testdataDir = "testdata"

var runDate = time.Date(2026, 11, 21, 18, 30, 0, 0, time.UTC)

func key(ip string, port uint16, proto string) model.AssetKey {
	return model.AssetKey{IP: netip.MustParseAddr(ip), Port: port, Proto: proto}
}

// fixture mirrors a small lab run: plain services, an admin panel, a
// staging app, a CMS, a false positive and a severity override.
func fixture() ([]Service, []Annotation) {
	svcs := []Service{
		{ServiceObs: model.ServiceObs{ID: 1, RunID: 7, Key: key("10.20.0.11", 443, "tcp"), Product: "nginx", Version: "1.27.4",
			CPE: "cpe:/a:f5:nginx:1.27.4"}, Hostname: "web.lab.test",
			HTTP: &HTTPSummary{URL: "https://10.20.0.11/", Status: 200, Title: "Welcome"},
			Detections: []model.Detection{
				{ServiceID: 1, SignatureID: "wordpress", Name: "WordPress", Category: "cms", Confidence: 90,
					Evidence: map[string]string{"meta_generator": "WordPress 6.5"}},
			}},
		{ServiceObs: model.ServiceObs{ID: 2, RunID: 7, Key: key("10.20.0.11", 22, "tcp"), Product: "OpenSSH", Version: "9.6p1",
			ExtraInfo: "protocol 2.0", Banner: "SSH-2.0-OpenSSH_9.6p1"}},
		{ServiceObs: model.ServiceObs{ID: 3, RunID: 7, Key: key("10.20.0.14", 80, "tcp"), Product: "Apache httpd", Version: "2.4.62"},
			HTTP: &HTTPSummary{URL: "http://10.20.0.14/", Status: 200, Title: "phpMyAdmin"},
			Detections: []model.Detection{
				{ServiceID: 3, SignatureID: "phpmyadmin", Name: "phpMyAdmin", Category: "admin-panel", Confidence: 100,
					Evidence: map[string]string{"title": "phpMyAdmin"},
					Meta: &model.SignatureMeta{CWE: []int{668}, Attack: []string{"T1078", "T1190"},
						Remediation: "Restrict phpMyAdmin to the administration network.",
						References:  []string{"https://docs.phpmyadmin.net/en/latest/setup.html#securing-your-phpmyadmin-installation"}}},
			}},
		{ServiceObs: model.ServiceObs{ID: 4, RunID: 7, Key: key("10.20.0.21", 8080, "tcp"), Product: "Jetty"},
			HTTP: &HTTPSummary{URL: "http://10.20.0.21:8080/", Status: 200, Title: "STAGING - shop"},
			Detections: []model.Detection{
				{ServiceID: 4, SignatureID: "staging-banner", Name: "Staging banner", Category: "staging", Confidence: 80},
			}},
		{ServiceObs: model.ServiceObs{ID: 5, RunID: 7, Key: key("10.20.0.30", 53, "udp"), Product: "dnsmasq", Version: "2.90"}},
		// False positive at service level: dropped with its detection.
		{ServiceObs: model.ServiceObs{ID: 6, RunID: 7, Key: key("10.20.0.31", 8443, "tcp")},
			Detections: []model.Detection{{ServiceID: 6, SignatureID: "grafana", Name: "Grafana", Category: "admin-panel", Confidence: 60}}},
		// Host-level false positive: every service of the host is dropped.
		{ServiceObs: model.ServiceObs{ID: 7, RunID: 7, Key: key("10.20.0.40", 21, "tcp"), Product: "vsftpd"}},
	}
	anns := []Annotation{
		{Key: key("10.20.0.31", 8443, "tcp"), FalsePositive: true, Comment: "honeypot"},
		{Key: model.AssetKey{IP: netip.MustParseAddr("10.20.0.40")}, FalsePositive: true},
		{Key: key("10.20.0.11", 22, "tcp"), Severity: "Low", Tags: []string{"Legacy SSH", "owner:ops"}, Comment: "Disable after the migration."},
	}
	return svcs, anns
}

func TestGoldenFindings(t *testing.T) {
	svcs, anns := fixture()
	have := must.Value(NewCodec().Marshal(BuildFindings(runDate, svcs, anns)))

	golden := filepath.Join(testdataDir, "golden_findings.json")
	if *update {
		must.Nil(os.WriteFile(golden, have, 0o644))
	}
	want := must.Value(os.ReadFile(golden))
	assert.True(t, bytes.Equal(want, have), "output differs from golden (go test ./internal/dojo -update)")
}

func TestBuildRules(t *testing.T) {
	svcs, anns := fixture()
	fs := BuildFindings(runDate, svcs, anns)
	by := map[string]model.Finding{}
	for _, f := range fs {
		by[f.UniqueIDFromTool] = f
	}
	cases := []struct {
		uid      string
		severity model.Severity
		title    string
	}{
		{"rampart:svc:10.20.0.11:443/tcp", model.SevInfo, "Open service 443/tcp nginx 1.27.4"},
		{"rampart:svc:10.20.0.11:22/tcp", model.SevLow, "Open service 22/tcp OpenSSH 9.6p1"},
		{"rampart:sig:10.20.0.11:443:wordpress", model.SevInfo, "Technology detected: WordPress"},
		{"rampart:sig:10.20.0.14:80:phpmyadmin", model.SevMedium, "Admin panel detected: phpMyAdmin"},
		{"rampart:sig:10.20.0.21:8080:staging-banner", model.SevMedium, "Staging environment detected: Staging banner"},
		{"rampart:svc:10.20.0.30:53/udp", model.SevInfo, "Open service 53/udp dnsmasq 2.90"},
	}
	for _, c := range cases {
		t.Run(c.uid, func(t *testing.T) {
			f, ok := by[c.uid]
			if !assert.True(t, ok) {
				return
			}
			assert.Equal(t, c.title, f.Title)
			assert.Equal(t, c.severity, f.Severity)
			assert.Equal(t, time.Date(2026, 11, 21, 0, 0, 0, 0, time.UTC), f.Date)
		})
	}
	for _, uid := range []string{"rampart:svc:10.20.0.31:8443/tcp", "rampart:sig:10.20.0.31:8443:grafana", "rampart:svc:10.20.0.40:21/tcp"} {
		_, ok := by[uid]
		assert.False(t, ok, "false positive %s was exported", uid)
	}
	ssh := by["rampart:svc:10.20.0.11:22/tcp"]
	assert.Equal(t, []string{"legacy-ssh", "owner:ops", "rampart", "service"}, ssh.Tags)
	assert.Contain(t, "Disable after the migration.", ssh.Description)
	assert.NotContain(t, "SSH-2.0-OpenSSH_9.6p1", ssh.Description)
	assert.Equal(t, "phpmyadmin", by["rampart:sig:10.20.0.14:80:phpmyadmin"].VulnIDFromTool)
	assert.Len(t, 8, fs) // 5 services + 3 detections
}

// Titles and the whole file must not depend on time of day, run id or
// input order: DefectDojo dedupes on a hash of title and description.
func TestDeterministic(t *testing.T) {
	svcs, anns := fixture()
	a := must.Value(NewCodec().Marshal(BuildFindings(runDate, svcs, anns)))

	svcs2, anns2 := fixture()
	for i := range svcs2 {
		svcs2[i].RunID = 99
		svcs2[i].ID += 100
	}
	for i, j := 0, len(svcs2)-1; i < j; i, j = i+1, j-1 {
		svcs2[i], svcs2[j] = svcs2[j], svcs2[i]
	}
	b := must.Value(NewCodec().Marshal(BuildFindings(runDate.Add(3*time.Hour), svcs2, anns2)))

	assert.True(t, bytes.Equal(a, b), "output not deterministic")
	for _, f := range BuildFindings(runDate, svcs, anns) {
		assert.NotContain(t, "2026", f.Title)
		assert.NotContain(t, "#", f.Title)
	}
}

func TestFindingsCarryCWEAndAttack(t *testing.T) {
	svcs, anns := fixture()
	fs := BuildFindings(runDate, svcs, anns)
	var got model.Finding
	for _, f := range fs {
		switch f.VulnIDFromTool {
		case "phpmyadmin":
			got = f
		case "staging-banner":
			assert.Equal(t, 0, f.CWE)
			assert.Equal(t, "", f.Mitigation)
			assert.Equal(t, "", f.References)
		}
	}

	assert.Equal(t, 668, got.CWE)
	assert.Equal(t, "Restrict phpMyAdmin to the administration network.", got.Mitigation)
	assert.Equal(t, "https://docs.phpmyadmin.net/en/latest/setup.html#securing-your-phpmyadmin-installation\n"+
		"https://cwe.mitre.org/data/definitions/668.html\n"+
		"https://attack.mitre.org/techniques/T1078/\n"+
		"https://attack.mitre.org/techniques/T1190/", got.References)
	tags := strings.Join(got.Tags, ",")
	assert.Contain(t, "attack-t1078", tags)
	assert.Contain(t, "attack-t1190", tags)

	// The metadata survives the codec.
	b := must.Value(NewCodec().Marshal([]model.Finding{got}))
	assert.Contain(t, `"cwe": 668`, string(b))
	back := must.Value(NewCodec().Unmarshal(b))
	assert.Equal(t, 668, back[0].CWE)
	assert.Equal(t, got.Mitigation, back[0].Mitigation)
	assert.Equal(t, got.References, back[0].References)
}

func TestUniqueIDsRoundTrip(t *testing.T) {
	k := key("10.20.0.11", 443, "tcp")
	assert.Equal(t, "rampart:svc:10.20.0.11:443/tcp", UniqueServiceID(k))
	assert.Equal(t, "rampart:sig:10.20.0.11:443:wordpress", UniqueSignatureID(k, "wordpress"))
	k.VHost = "shop.lab.test"
	assert.Equal(t, "rampart:svc:10.20.0.11:443/tcp@shop.lab.test", UniqueServiceID(k))

	for uid, want := range map[string]string{
		UniqueServiceID(key("10.20.0.11", 443, "tcp")): "10.20.0.11:443",
		UniqueServiceID(k): "10.20.0.11:443",
		UniqueSignatureID(key("10.20.0.14", 80, "tcp"), "phpmyadmin"): "10.20.0.14:80",
		"rampart:sig:10.20.0.14:80:phpmyadmin@a.b.test":               "10.20.0.14:80",
		UniqueServiceID(key("2001:db8::1", 53, "udp")):                "[2001:db8::1]:53",
	} {
		ip, port, ok := ParseUniqueID(uid)
		assert.True(t, ok, uid)
		assert.Equal(t, want, netip.AddrPortFrom(ip, port).String())
	}
	for _, foreign := range []string{"nessus:123", "asi:svc:10.20.0.11:443/tcp", "rampart:svc:nope"} {
		_, _, ok := ParseUniqueID(foreign)
		assert.False(t, ok, foreign)
	}
}

// DefectDojo hashes Generic Findings by title and description, so a banner
// that changes between runs must not change the finding.
func TestDescriptionIgnoresBanner(t *testing.T) {
	k := key("10.20.0.25", 25, "tcp")
	mk := func(banner string) model.Finding {
		s := Service{ServiceObs: model.ServiceObs{Key: k, Product: "Postfix smtpd", Banner: banner}}
		fs := BuildFindings(time.Date(2026, 11, 21, 9, 0, 0, 0, time.UTC), []Service{s}, nil)
		assert.Len(t, 1, fs)
		return fs[0]
	}

	a := mk("220 mail ESMTP Postfix Sat, 21 Nov 2026 09:00:01 +0000")
	b := mk("220 mail ESMTP Postfix Sat, 21 Nov 2026 10:13:44 +0000")

	assert.Equal(t, a.Title, b.Title)
	assert.Equal(t, a.Description, b.Description)
}

// A host-level annotation applies even when stored with a proto or vhost.
func TestHostAnnotationKeyNormalised(t *testing.T) {
	ip := netip.MustParseAddr("10.20.0.26")
	s := Service{ServiceObs: model.ServiceObs{Key: model.AssetKey{IP: ip, Port: 80, Proto: "tcp"}}}
	anns := []Annotation{{Key: model.AssetKey{IP: ip, Proto: "tcp"}, FalsePositive: true}}

	assert.Len(t, 0, BuildFindings(time.Time{}, []Service{s}, anns))
}

func TestDetectionSeverity(t *testing.T) {
	assert.Equal(t, model.SevInfo, DetectionSeverity(model.Detection{Category: "cms"}))
	assert.Equal(t, model.SevMedium, DetectionSeverity(model.Detection{Category: "admin-panel"}))
	assert.Equal(t, model.SevHigh, DetectionSeverity(model.Detection{Category: "cms", Evidence: map[string]string{"severity": "high"}}))
}
