package dojo

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ctx42/testing/pkg/assert"
	"github.com/ctx42/testing/pkg/must"

	"github.com/chrobson/ramparteye/internal/model"
)

func TestRoundTrip(t *testing.T) {
	day := time.Date(2026, 11, 21, 0, 0, 0, 0, time.UTC)
	in := []model.Finding{
		{Title: "Admin panel detected: phpMyAdmin", Severity: model.SevMedium, Description: "d1", Date: day,
			UniqueIDFromTool: "rampart:sig:10.20.0.14:80:phpmyadmin", VulnIDFromTool: "phpmyadmin",
			Endpoints: []model.AssetKey{key("10.20.0.14", 80, "tcp")}, Tags: []string{"admin-panel", "rampart"}},
		{Title: "Open service 22/tcp OpenSSH", Severity: model.SevInfo, Description: "d2", Date: day,
			UniqueIDFromTool: "rampart:svc:10.20.0.11:22/tcp",
			Endpoints:        []model.AssetKey{key("10.20.0.11", 22, "tcp")}, Tags: []string{"rampart", "service"}},
		{Title: "Open service 53/udp", Severity: model.SevInfo, Description: "d3",
			UniqueIDFromTool: "rampart:svc:2001:db8::1:53/udp", Endpoints: []model.AssetKey{key("2001:db8::1", 53, "udp")}},
	}
	c := NewCodec()

	b := must.Value(c.Marshal(in))
	out := must.Value(c.Unmarshal(b))

	assert.Equal(t, in, out)
	assert.True(t, bytes.Equal(b, must.Value(c.Marshal(out))), "second marshal differs")
}

func TestMarshalRejectsDuplicateIDs(t *testing.T) {
	f := model.Finding{Title: "x", Severity: model.SevInfo, Description: "d", UniqueIDFromTool: "rampart:svc:10.20.0.1:80/tcp"}

	_, err := NewCodec().Marshal([]model.Finding{f, f})

	assert.ErrorContain(t, "duplicate unique_id_from_tool", err)
}

func TestUnmarshalLenient(t *testing.T) {
	doc := `{"findings":[{"title":"t","severity":"informational","description":"d","cwe":79,
		"date":"2026-11-21T10:00:00Z","endpoints":["https://10.20.0.5/login","admin.lab.test:8443",{"host":"10.20.0.6","port":"8080","protocol":"http"}]}]}`

	fs := must.Value(NewCodec().Unmarshal([]byte(doc)))

	f := fs[0]
	assert.Equal(t, model.SevInfo, f.Severity)
	assert.Equal(t, "2026-11-21", f.Date.Format(dateLayout))
	assert.Equal(t, 79, f.CWE)
	assert.Equal(t, []model.AssetKey{
		key("10.20.0.5", 443, "tcp"),
		{Port: 8443, Proto: "tcp", VHost: "admin.lab.test"},
		key("10.20.0.6", 8080, "tcp"),
	}, f.Endpoints)
	_, err := NewCodec().Unmarshal([]byte(`{"findings":[{"title":"t","severity":"Info"}]}`))
	assert.Error(t, err)
	_, err = NewCodec().Unmarshal([]byte(`{"findings":[{"title":"t","severity":"Severe","description":"d"}]}`))
	assert.Error(t, err)
}

func TestVHostEndpoint(t *testing.T) {
	k := key("10.20.0.11", 443, "tcp")
	k.VHost = "shop.lab.test"

	e := endpointFromKey(k)

	assert.Equal(t, wireEndpoint{Host: "shop.lab.test", Port: 443, Protocol: "https"}, e)
	assert.Equal(t, "tcp", endpointFromKey(key("10.20.0.1", 5432, "tcp")).Protocol)
}

func TestValidateGolden(t *testing.T) {
	b := must.Value(os.ReadFile(filepath.Join(testdataDir, "golden_findings.json")))

	assert.NoError(t, Validate(b))
}

func TestValidateRejects(t *testing.T) {
	base := func() map[string]any {
		return map[string]any{
			"title": "t", "severity": "Info", "description": "d", "date": "2026-11-21",
			"unique_id_from_tool": "rampart:svc:10.20.0.1:80/tcp",
			"endpoints":           []any{map[string]any{"host": "10.20.0.1", "port": 80, "protocol": "http"}},
			"tags":                []any{"rampart"},
		}
	}
	enc := func(top map[string]any) []byte { return must.Value(json.Marshal(top)) }
	one := func(mut func(map[string]any)) []byte {
		f := base()
		mut(f)
		return enc(map[string]any{"findings": []any{f}})
	}
	assert.NoError(t, Validate(one(func(map[string]any) {})))

	cases := map[string][]byte{
		"extra finding key":   one(func(f map[string]any) { f["cvssv3"] = "AV:N" }),
		"extra top-level key": enc(map[string]any{"findings": []any{base()}, "name": "x"}),
		"duplicate ids":       enc(map[string]any{"findings": []any{base(), base()}}),
		"missing title":       one(func(f map[string]any) { delete(f, "title") }),
		"empty description":   one(func(f map[string]any) { f["description"] = " " }),
		"bad severity":        one(func(f map[string]any) { f["severity"] = "info" }),
		"bad date":            one(func(f map[string]any) { f["date"] = "21.11.2026" }),
		"missing unique id":   one(func(f map[string]any) { delete(f, "unique_id_from_tool") }),
		"endpoint extra key":  one(func(f map[string]any) { f["endpoints"] = []any{map[string]any{"host": "h", "ip": "1"}} }),
		"endpoint no host":    one(func(f map[string]any) { f["endpoints"] = []any{map[string]any{"port": 80}} }),
		"endpoint bad port":   one(func(f map[string]any) { f["endpoints"] = []any{map[string]any{"host": "h", "port": 70000}} }),
		"endpoint string":     one(func(f map[string]any) { f["endpoints"] = []any{"http://h/"} }),
		"tags not strings":    one(func(f map[string]any) { f["tags"] = []any{1} }),
		"title not string":    one(func(f map[string]any) { f["title"] = 5 }),
		"cwe as string":       one(func(f map[string]any) { f["cwe"] = "CWE-306" }),
		"cwe negative":        one(func(f map[string]any) { f["cwe"] = -1 }),
		"mitigation number":   one(func(f map[string]any) { f["mitigation"] = 5 }),
		"title too long":      one(func(f map[string]any) { f["title"] = strings.Repeat("t", 501) }),
		"steps not string":    one(func(f map[string]any) { f["steps_to_reproduce"] = 1 }),
		"no findings key":     []byte(`{}`),
		"not json":            []byte(`{"findings":`),
		"trailing data":       append(one(func(map[string]any) {}), []byte(`{}`)...),
	}
	for name, b := range cases {
		t.Run(name, func(t *testing.T) { assert.Error(t, Validate(b)) })
	}
	ok := one(func(f map[string]any) { f["cwe"] = 306; f["mitigation"] = "m"; f["references"] = "https://a" })
	assert.NoError(t, Validate(ok))
}
