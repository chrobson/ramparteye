package sig

import (
	"strings"
	"testing"

	"github.com/ctx42/testing/pkg/assert"
)

func TestSeverityOutdatedValidation(t *testing.T) {
	base := "id: x-test\nname: X\ncategory: other\nconfidence: 50\n"
	bad := map[string]string{
		"severity":             base + "severity: urgent\nmatchers:\n  - {type: title, regex: x}\n",
		"outdated-below":       base + "outdated: {below: latest, severity: high}\nmatchers:\n  - {type: title, regex: x}\n",
		"outdated-severity":    base + "outdated: {below: '6.0', severity: huge}\nmatchers:\n  - {type: title, regex: x}\n",
		"negate-path":          base + "matchers:\n  - {type: title, regex: x}\n  - {type: path, path: /a, status: [200], negate: true}\n",
		"negate-cookie":        base + "matchers:\n  - {type: cookie, name: sid, negate: true}\n",
		"version-only-nogroup": base + "matchers:\n  - {type: title, regex: x}\n  - {type: body, regex: 'v[0-9]', version_only: true}\n",
		"version-only-and":     base + "condition: and\nmatchers:\n  - {type: title, regex: x}\n  - {type: body, regex: 'v(?P<version>[0-9])', version_only: true}\n",
		"version-only-alone":   base + "matchers:\n  - {type: body, regex: 'v(?P<version>[0-9])', version_only: true}\n",
		"version-only-negated": base + "matchers:\n  - {type: title, regex: x}\n  - {type: body, regex: 'v(?P<version>[0-9])', version_only: true, negate: true}\n",
	}
	for name, y := range bad {
		_, err := Parse([]byte(y))

		assert.Error(t, err, "%s: accepted", name)
	}

	ok := base + "severity: high\noutdated: {below: '6.0', severity: critical}\nmatchers:\n" +
		"  - {type: title, regex: x}\n  - {type: service, banner: auth, negate: true}\n" +
		"  - {type: path, path: /readme.html, status: [200], regex: 'Version (?P<version>[0-9.]+)', version_only: true}\n"
	_, err := Parse([]byte(ok))
	assert.NoError(t, err)
}

func TestCompareVersions(t *testing.T) {
	tests := []struct {
		a, b string
		want int
		ok   bool
	}{
		{"4.7", "6.0", -1, true},
		{"6.0", "6", 0, true},
		{"6.4.2", "6.0", 1, true},
		{"5.9.10", "5.10", -1, true},
		{"2.0.18-beta", "2.0.18", 0, true},
		{"9.6.0 or later", "10", -1, true},
		{"", "1.0", 0, false},
		{"latest", "1.0", 0, false},
		{"1234567890.1", "1", 0, false}, // overlong part
	}
	for _, tt := range tests {
		got, ok := CompareVersions(tt.a, tt.b)

		assert.Equal(t, tt.want, got, "%q vs %q", tt.a, tt.b)
		assert.Equal(t, tt.ok, ok, "%q vs %q", tt.a, tt.b)
	}
}

func TestDojoSeverity(t *testing.T) {
	assert.Equal(t, "High", DojoSeverity("high"))
	assert.Equal(t, "", DojoSeverity(""))
}

func TestOutdatedRaisesSeverity(t *testing.T) {
	s := mustParse(t, "id: srv\nname: S\ncategory: server\nconfidence: 5\nseverity: low\n"+
		"outdated: {below: '2.0', severity: high}\nmatchers:\n  - {type: header, name: Server, regex: 'Srv/(?P<version>[0-9.]+)'}\n")
	e := NewEngine([]*Signature{s}, nil)

	old := match(e, svc(80, ""), httpObs(80, "", "", map[string][]string{"Server": {"Srv/1.9"}}))
	cur := match(e, svc(80, ""), httpObs(80, "", "", map[string][]string{"Server": {"Srv/2.1"}}))

	assert.Len(t, 1, old)
	assert.Equal(t, "High", old[0].Evidence["severity"])
	assert.Equal(t, "version 1.9 < 2.0", old[0].Evidence["outdated"])
	assert.Len(t, 1, cur)
	assert.Equal(t, "Low", cur[0].Evidence["severity"])
	assert.HasNoKey(t, "outdated", cur[0].Evidence)
}

func TestNegatedHTTPMatcherNeedsResponse(t *testing.T) {
	s := mustParse(t, "id: no-hsts\nname: No HSTS\ncategory: other\nconfidence: 50\nmatchers:\n  - {type: header, name: Strict-Transport-Security, negate: true}\n")
	e := NewEngine([]*Signature{s}, nil)

	ds := match(e, svc(6379, ""), httpObs(6379, "", "", nil))

	assert.Len(t, 1, ds)
	assert.True(t, strings.HasPrefix(ds[0].Evidence["not:header"], "no match"))

	o := httpObs(6379, "", "", nil)
	o.Status = 0
	assert.Len(t, 0, match(e, svc(6379, ""), o))
}
