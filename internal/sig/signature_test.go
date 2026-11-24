package sig

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/ctx42/testing/pkg/assert"
	"github.com/ctx42/testing/pkg/must"

	"github.com/chrobson/ramparteye/internal/sig/builtin"
)

func builtins(t *testing.T) []*Signature {
	t.Helper()
	sigs, err := Builtin()
	if !assert.NoError(t, err) {
		t.FailNow()
	}
	return sigs
}

func TestBuiltinSignaturesLoad(t *testing.T) {
	sigs := builtins(t)

	required := []string{"wordpress", "joomla", "drupal", "nginx", "apache-httpd", "iis", "tomcat", "tomcat-manager",
		"jenkins", "grafana", "gitlab", "phpmyadmin", "kibana", "admin-panel", "login-page", "spring-boot-actuator",
		"apache-server-status", "staging-env", "mosquitto-mqtt", "iot-webui", "tls-self-signed", "tls-expired",
		"adminer", "gitea", "dvwa", "nginx-proxy-manager", "traefik-dashboard", "toxiproxy-api", "rabbitmq-management",
		"rabbitmq-amqp", "httpbin", "redis", "redis-noauth", "ftp", "vsftpd", "postgresql", "mysql"}
	ids := map[string]*Signature{}
	for _, s := range sigs {
		ids[s.ID] = s
		assert.NotEmpty(t, s.Raw, s.ID)
		assert.NotEmpty(t, s.Description, s.ID)
		assert.Equal(t, SourceBuiltin, s.Source, s.ID)
		assert.True(t, s.Enabled, s.ID)
	}
	for _, id := range required {
		assert.HasKey(t, id, ids)
	}
}

func TestAllBuiltinsValid(t *testing.T) {
	sigs, err := Load(builtin.FS)

	assert.NoError(t, err)
	assert.Len(t, 41, sigs)
	for _, s := range sigs {
		assert.Len(t, 0, Validate(s), s.ID)
	}
}

// Every field of every built-in, comments included, is English.
func TestBuiltinsEnglish(t *testing.T) {
	polish := regexp.MustCompile("(?i)[\u0105\u0107\u0119\u0142\u0144\u00f3\u015b\u017a\u017c]")
	for _, s := range builtins(t) {
		assert.False(t, polish.MatchString(s.Raw), "%s: non-English text: %q", s.ID, polish.FindString(s.Raw))
	}
}

func TestBuiltinPathProbeFlag(t *testing.T) {
	byID := map[string]*Signature{}
	for _, s := range builtins(t) {
		byID[s.ID] = s
	}

	assert.True(t, byID["tomcat-manager"].PathProbe)
	assert.True(t, byID["wordpress"].PathProbe) // version-only probes count too
	assert.False(t, byID["nginx"].PathProbe)
	assert.False(t, byID["redis"].PathProbe)
}

func TestParseDefaults(t *testing.T) {
	s := must.Value(Parse([]byte("id: x-def\nname: X\ncategory: other\nconfidence: 5\nmatchers:\n  - {type: path, path: /a, status: [200]}\n")))

	assert.Equal(t, SourceCustom, s.Source)
	assert.True(t, s.Enabled)
	assert.True(t, s.PathProbe)
	assert.Equal(t, "GET", s.Matchers[0].Method)
}

func TestValidGoldenFiles(t *testing.T) {
	sigs, err := Load(os.DirFS("testdata/valid"))

	assert.NoError(t, err)
	assert.Len(t, 2, sigs)
	for _, s := range sigs {
		for _, m := range s.Matchers {
			if m.Type == TypePath {
				assert.NotEmpty(t, m.Method, "%s: method not defaulted", s.ID)
			}
		}
	}
}

// Every file in testdata/invalid starts with "# want: <substring>" naming
// the validator error it must produce.
func TestInvalidGoldenFiles(t *testing.T) {
	files, _ := filepath.Glob("testdata/invalid/*.yaml")
	assert.True(t, len(files) >= 15, "only %d invalid fixtures", len(files))
	for _, f := range files {
		t.Run(filepath.Base(f), func(t *testing.T) {
			b := must.Value(os.ReadFile(f))
			first, _, _ := strings.Cut(string(b), "\n")
			want, ok := strings.CutPrefix(first, "# want: ")
			if !assert.True(t, ok, "fixture must start with '# want: '") {
				return
			}

			_, err := Parse(b)

			assert.ErrorContain(t, want, err)
		})
	}
}

func TestValidateListsEveryProblem(t *testing.T) {
	s := &Signature{ID: "Bad ID", Category: "nope", Confidence: 0}

	errs := Validate(s)

	assert.True(t, len(errs) >= 4, "errors: %v", errs)
}

func TestValidateSource(t *testing.T) {
	s := must.Value(Parse([]byte("id: x-src\nname: X\ncategory: other\nconfidence: 5\nmatchers:\n  - {type: title, regex: x}\n")))
	for _, src := range []string{SourceBuiltin, SourceCustom, SourceNuclei} {
		s.Source = src
		assert.Len(t, 0, Validate(s), src)
	}

	s.Source = "plugin"

	assert.Len(t, 1, Validate(s))
}

func TestLoadRejectsDuplicates(t *testing.T) {
	doc := []byte("id: dup\nname: D\ncategory: other\nconfidence: 5\nmatchers:\n  - {type: title, regex: x}\n")
	fsys := fstest.MapFS{"a.yaml": {Data: doc}, "b.yml": {Data: doc}, "notes.txt": {Data: []byte("x")}}

	sigs, err := Load(fsys)

	assert.ErrorContain(t, "duplicate id", err)
	assert.Len(t, 1, sigs)
}

func TestParseRejectsHugeDocument(t *testing.T) {
	_, err := Parse(make([]byte, MaxYAMLBytes+1))
	assert.ErrorContain(t, "too large", err)

	_, err = Parse(nil)
	assert.ErrorContain(t, "empty signature", err)
}

const metaBase = `id: meta-test
name: Meta test
category: server
confidence: 80
matchers:
  - type: title
    regex: 'x'
`

func TestSignatureMetaValid(t *testing.T) {
	s := must.Value(Parse([]byte(metaBase + `cwe: [306, 668]
attack: [T1190, T1078.001]
remediation: 'Enable   authentication.'
references:
  - https://redis.io/docs/latest/operate/oss_and_stack/management/security/
  - http://example.test/a
`)))

	m := s.Meta()

	assert.NotNil(t, m)
	assert.Equal(t, []int{306, 668}, m.CWE)
	assert.Equal(t, "T1078.001", m.Attack[1])
	assert.Equal(t, "Enable authentication.", m.Remediation)
	assert.Len(t, 2, m.References)

	// Without the optional fields the signature loads unchanged and has no meta.
	plain := must.Value(Parse([]byte(metaBase)))
	assert.Nil(t, plain.Meta())
}

func TestSignatureMetaInvalid(t *testing.T) {
	cases := map[string]string{
		"attack: [T190]":                      "MITRE ATT&CK technique id",
		"attack: [t1190]":                     "MITRE ATT&CK technique id",
		"attack: [T1190.1]":                   "MITRE ATT&CK technique id",
		"references: [ftp://x.test/a]":        "http:// or https:// URL",
		"references: ['javascript:alert(1)']": "http:// or https:// URL",
		"references: [/relative]":             "http:// or https:// URL",
		"cwe: [0]":                            "CWE number",
		"cwe: [CWE-306]":                      "yaml",
		"mitigation: x":                       "yaml", // unknown key stays rejected
	}
	for extra, want := range cases {
		_, err := Parse([]byte(metaBase + extra + "\n"))

		assert.ErrorContain(t, want, err, extra)
	}
}

func TestBuiltinMetaCoverage(t *testing.T) {
	sigs := builtins(t)
	with := 0
	for _, s := range sigs {
		if m := s.Meta(); m != nil && len(m.CWE) > 0 && m.Remediation != "" {
			with++
		}
	}
	assert.True(t, with*10 >= len(sigs)*8, "only %d of %d built-ins have cwe and remediation", with, len(sigs))
	for _, s := range sigs {
		if s.ID == "redis-noauth" || s.ID == "traefik-dashboard" {
			assert.Equal(t, 306, s.CWE[0], s.ID)
		}
	}
}

func TestRegexCostBounded(t *testing.T) {
	tests := []struct {
		testN string

		regex string
		want  string
	}{
		{"counted repeat over 100", `.{101}`, "counted repeat"},
		{"repeat min over 100", `a{200,}`, "counted repeat"},
		{"large program from nested repeats", `(?:a{100}){10}(?:b{100}){10}(?:c{100}){10}d{100}`, "regex too complex"},
		{"long repeated wildcards", strings.Repeat(`.{99}`, 40), "regex too complex"},
	}
	for _, tt := range tests {
		t.Run(tt.testN, func(t *testing.T) {
			doc := "id: x-cost\nname: X\ncategory: other\nconfidence: 5\nmatchers:\n  - type: body\n    regex: '" + tt.regex + "'\n"

			_, err := Parse([]byte(doc))

			assert.ErrorContain(t, tt.want, err)
		})
	}
	_, err := Parse([]byte("id: x-ok\nname: X\ncategory: other\nconfidence: 5\nmatchers:\n  - {type: body, regex: '[0-9a-f]{32}'}\n"))
	assert.NoError(t, err)
}

// The instruction limit is maxRegexInst (500): exactly 500 passes, 501
// and the 503-instruction ".{100}" x5 pattern do not.
func TestRegexInstLimit(t *testing.T) {
	body := func(re string) []byte {
		return []byte("id: x-inst\nname: X\ncategory: other\nconfidence: 5\nmatchers:\n  - type: body\n    regex: '" + re + "'\n")
	}
	four := strings.Repeat(`.{100}`, 4)

	_, err := Parse(body(four + `.{97}\x00`)) // 500 instructions
	assert.NoError(t, err)

	_, err = Parse(body(four + `.{98}\x00`)) // 501
	assert.ErrorContain(t, "regex too complex (501 instructions, max 500)", err)

	_, err = Parse(body(strings.Repeat(`.{100}`, 5) + `\x00`)) // 503
	assert.ErrorContain(t, "regex too complex", err)
}

// Only allowlisted request headers pass, so a path probe cannot override
// the method, rewrite the URL or spoof the client address.
func TestPathProbeHeaderAllowlist(t *testing.T) {
	refused := []string{"X-HTTP-Method-Override", "X-HTTP-Method", "X-Method-Override", "X-Original-URL",
		"X-Rewrite-URL", "Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "Max-Forwards", "Range", "X-Custom"}
	for _, h := range refused {
		doc := "id: x-hdr\nname: X\ncategory: other\nconfidence: 5\nmatchers:\n  - type: path\n    path: /a\n    status: [200]\n    headers: {" + h + ": x}\n"

		_, err := Parse([]byte(doc))

		assert.ErrorContain(t, `request header "`+h+`" is not allowed`, err)
	}
	for _, h := range []string{"Accept", "Accept-Language", "X-Requested-With", "If-None-Match", "If-Modified-Since"} {
		doc := "id: x-hdr\nname: X\ncategory: other\nconfidence: 5\nmatchers:\n  - type: path\n    path: /a\n    status: [200]\n    headers: {" + h + ": x}\n"

		_, err := Parse([]byte(doc))

		assert.NoError(t, err, h)
	}
}

func TestPathEncodingsRefused(t *testing.T) {
	for _, p := range []string{"/a%25", "/a%0a", "/a%1F", "/a%7f", "/a%2e"} {
		doc := "id: x-enc\nname: X\ncategory: other\nconfidence: 5\nmatchers:\n  - {type: path, path: '" + p + "', status: [200]}\n"

		_, err := Parse([]byte(doc))

		assert.Error(t, err, p)
	}
}

// Polish titles are matched through RE2 \x{...} escapes, so the YAML stays
// ASCII; (?i) covers upper-case forms.
func TestBuiltinPolishTitles(t *testing.T) {
	byID := map[string]*Signature{}
	for _, s := range builtins(t) {
		byID[s.ID] = s
	}
	tests := []struct {
		id, title string
	}{
		{"admin-panel", "Panel administracyjny"},
		{"admin-panel", "Panel administratora - logowanie"},
		{"admin-panel", "Panel zarz\u0105dzania"},
		{"admin-panel", "PANEL ZARZ\u0104DZANIA"},
		{"staging-env", "\u015arodowisko testowe"},
		{"staging-env", "Sklep - \u015aRODOWISKO DEWELOPERSKIE"},
	}
	for _, tt := range tests {
		e := NewEngine([]*Signature{byID[tt.id]}, nil)

		ds := match(e, svc(80, ""), httpObs(80, tt.title, "", nil))

		assert.Len(t, 1, ds, "%s: %q", tt.id, tt.title)
	}
}

func TestReservedIDsRejected(t *testing.T) {
	for _, id := range []string{"import", "new", "backtest"} {
		_, err := Parse([]byte("id: " + id + "\nname: x\ncategory: other\nconfidence: 50\n" +
			"matchers:\n  - type: title\n    regex: 'x'\n"))

		assert.ErrorContain(t, "id "+id+" is reserved", err)
	}
}
