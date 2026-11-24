package nuclei

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ctx42/testing/pkg/assert"

	"github.com/chrobson/ramparteye/internal/sig"
)

func load(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func convertFile(t *testing.T, name string) (*sig.Signature, error) {
	t.Helper()
	return Convert(load(t, name))
}

func mustConvert(t *testing.T, name string) *sig.Signature {
	t.Helper()
	s, err := convertFile(t, name)
	if !assert.NoError(t, err) {
		t.FailNow()
	}
	return s
}

func TestConvertRejects(t *testing.T) {
	tt := []struct {
		file   string
		reason string
	}{
		{"reject_post.yaml", "method POST not allowed"},
		{"reject_body.yaml", "request body"},
		{"reject_payloads.yaml", "payloads"},
		{"reject_fuzzing.yaml", "fuzzing"},
		{"reject_interactsh.yaml", "interactsh"},
		{"reject_two_requests.yaml", "more than one request"},
		{"reject_raw.yaml", "raw requests"},
		{"reject_headless.yaml", "protocol headless"},
		{"reject_network.yaml", "protocol network"},
		{"reject_dns.yaml", "protocol dns"},
		{"reject_code.yaml", "protocol code"},
		{"reject_dsl.yaml", "matcher type dsl"},
		{"reject_variable.yaml", "{{randstr}}"},
		{"reject_negative_status.yaml", "negative"},
		{"reject_user_agent.yaml", "User-Agent"},
		{"reject_alias.yaml", "anchors and aliases"},
		{"reject_traversal.yaml", ".."},
		{"reject_or_word_and.yaml", "condition and"},
		{"reject_cost.yaml", "regex"},
	}
	for _, tc := range tt {
		t.Run(tc.file, func(t *testing.T) {
			s, err := convertFile(t, tc.file)

			assert.Nil(t, s)
			var re *RejectError
			if assert.True(t, errors.As(err, &re), "%v", err) {
				assert.Contain(t, tc.reason, re.Reason)
			}
		})
	}
}

func TestConvertRejectExactReason(t *testing.T) {
	_, err := convertFile(t, "reject_post.yaml")

	var re *RejectError
	assert.True(t, errors.As(err, &re))
	assert.Equal(t, "method POST not allowed", re.Reason)
}

func TestConvertServerStatus(t *testing.T) {
	s := mustConvert(t, "accept_server_status.yaml")

	assert.Equal(t, "nuclei-apache-server-status-exposed", s.ID)
	assert.Equal(t, "Apache Server Status Exposed", s.Name)
	assert.Equal(t, sig.SourceNuclei, s.Source)
	assert.False(t, s.Enabled)
	assert.True(t, s.PathProbe)
	assert.Equal(t, "medium", s.Severity)
	assert.Equal(t, "and", s.Condition)
	assert.Equal(t, []int{200}, s.CWE)
	assert.Equal(t, "The /server-status page is publicly reachable.", s.Description)
	assert.Equal(t, "Restrict /server-status to monitoring addresses.", s.Remediation)
	assert.Equal(t, []string{"https://httpd.apache.org/docs/2.4/mod/mod_status.html"}, s.References)
	assert.Equal(t, "other", s.Category)
	assert.Len(t, 2, s.Matchers)
	assert.Equal(t, sig.TypePath, s.Matchers[0].Type)
	assert.Equal(t, "/server-status", s.Matchers[0].Path)
	assert.Equal(t, []int{200}, s.Matchers[0].Status)
	assert.Equal(t, sig.TypePath, s.Matchers[1].Type)
	assert.Equal(t, "(?:Apache Server Status)|(?:Server Version)", s.Matchers[1].Regex)
}

func TestConvertBaseHeaderAndBody(t *testing.T) {
	s := mustConvert(t, "accept_base_header.yaml")

	assert.Equal(t, "nuclei-nginx_detect-v1", s.ID)
	assert.False(t, s.PathProbe)
	assert.Equal(t, "info", s.Severity)
	assert.Equal(t, "or", s.Condition)
	assert.Len(t, 2, s.Matchers)
	assert.Equal(t, sig.TypeHeader, s.Matchers[0].Type)
	assert.Equal(t, "Server", s.Matchers[0].Name)
	assert.Equal(t, "nginx", s.Matchers[0].Regex)
	assert.Equal(t, sig.TypeBody, s.Matchers[1].Type)
	assert.Equal(t, `(?i)Welcome to nginx`, s.Matchers[1].Regex)
}

func TestConvertRegexAndHeaderPart(t *testing.T) {
	s := mustConvert(t, "accept_regex_and.yaml")

	assert.Equal(t, "nuclei-grafana-login", s.ID)
	assert.Equal(t, "info", s.Severity) // unknown severity
	assert.Equal(t, []int{200, 306}, s.CWE)
	assert.True(t, s.PathProbe)
	assert.Len(t, 3, s.Matchers)
	assert.Equal(t, "/login", s.Matchers[0].Path)
	assert.Equal(t, `(?:<title>Grafana</title>)|(?:grafana-app)`, s.Matchers[0].Regex)
	assert.Equal(t, "content-type", s.Matchers[1].Header)
	assert.Equal(t, `(?i)text/html`, s.Matchers[1].HeaderRegex)
	assert.Equal(t, []int{200, 302}, s.Matchers[2].Status)
}

func TestConvertWordAndExpands(t *testing.T) {
	s := mustConvert(t, "accept_word_and.yaml")

	assert.Equal(t, "and", s.Condition)
	assert.False(t, s.PathProbe) // {{BaseURL}}/ is the base page
	assert.Len(t, 2, s.Matchers)
	assert.Equal(t, "alpha", s.Matchers[0].Regex)
	assert.Equal(t, "beta", s.Matchers[1].Regex)
	assert.Equal(t, "high", s.Severity)
}

func TestConvertNegativeBody(t *testing.T) {
	s := mustConvert(t, "accept_negative_body.yaml")

	assert.Len(t, 2, s.Matchers)
	assert.Equal(t, sig.TypeBody, s.Matchers[1].Type)
	assert.True(t, s.Matchers[1].Negate)
}

func TestConvertHeadProbeWithHeaders(t *testing.T) {
	s := mustConvert(t, "accept_head_headers.yaml")

	assert.True(t, s.PathProbe)
	assert.Equal(t, "HEAD", s.Matchers[0].Method)
	assert.Equal(t, "/status?full=1", s.Matchers[0].Path)
	assert.Equal(t, map[string]string{"Accept": "text/html"}, s.Matchers[0].Headers)
}

func TestPathProbeFlag(t *testing.T) {
	tt := []struct {
		path string
		want bool
	}{
		{"{{BaseURL}}", false},
		{"{{BaseURL}}/", false},
		{"{{BaseURL}}/server-status", true},
		{"{{RootURL}}/x", true},
		{"{{BaseURL}}?a=1", true},
	}
	for _, tc := range tt {
		t.Run(tc.path, func(t *testing.T) {
			doc := "id: p\ninfo: {name: P, severity: low}\nhttp:\n  - path: [\"" + tc.path + "\"]\n    matchers:\n      - type: status\n        status: [200]\n"

			s, err := Convert([]byte(doc))

			assert.NoError(t, err)
			assert.Equal(t, tc.want, s.PathProbe)
			assert.False(t, s.Enabled)
			assert.Equal(t, sig.SourceNuclei, s.Source)
		})
	}
}

func TestConvertRawRoundTrips(t *testing.T) {
	for _, f := range []string{"accept_server_status.yaml", "accept_base_header.yaml", "accept_regex_and.yaml",
		"accept_word_and.yaml", "accept_negative_body.yaml", "accept_head_headers.yaml"} {
		t.Run(f, func(t *testing.T) {
			s := mustConvert(t, f)

			again, err := sig.Parse([]byte(s.Raw))

			assert.NoError(t, err)
			again.Source, again.Enabled = s.Source, s.Enabled
			assert.Equal(t, s, again)
		})
	}
}

func TestConvertSizeLimit(t *testing.T) {
	doc := "id: big\ninfo: {name: x, severity: info}\n# " + strings.Repeat("a", MaxTemplateBytes) + "\n"

	_, err := Convert([]byte(doc))

	var re *RejectError
	assert.True(t, errors.As(err, &re))
	assert.Contain(t, "too large", re.Reason)
}

func TestConvertMalformedAndEmpty(t *testing.T) {
	for _, doc := range []string{"", "::: not yaml [", "- a\n- b\n", "id: x\n"} {
		s, err := Convert([]byte(doc))

		assert.Nil(t, s, doc)
		var re *RejectError
		assert.True(t, errors.As(err, &re), doc)
	}
}

func TestConvertDeepNesting(t *testing.T) {
	doc := "id: x\ninfo: {name: x, severity: info}\nhttp: " + strings.Repeat("[", 500) + strings.Repeat("]", 500) + "\n"

	_, err := Convert([]byte(doc))

	var re *RejectError
	assert.True(t, errors.As(err, &re))
}

func TestRejectErrorMessage(t *testing.T) {
	err := &RejectError{Reason: "method POST not allowed"}

	assert.Equal(t, "nuclei template rejected: method POST not allowed", err.Error())
}
