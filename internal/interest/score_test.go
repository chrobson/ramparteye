package interest

import (
	"strings"
	"testing"

	"github.com/ctx42/testing/pkg/assert"
)

func hasReason(r Result, rule string, pts int) bool {
	for _, x := range r.Reasons {
		if strings.HasPrefix(x.Rule, rule) && x.Points == pts {
			return true
		}
	}
	return false
}

func TestScore_rules(t *testing.T) {
	login := []Detection{{Signature: "login-page", Category: "other", Severity: "Info"}}
	cases := []struct {
		name   string
		in     Input
		score  int
		reason string
		points int
	}{
		{"nothing", Input{Port: 80, Service: "http"}, 0, "", 0},
		{"critical full confidence", Input{Detections: []Detection{{Name: "X", Severity: "Critical", Confidence: 100}}}, 60, "detection X: Critical", 60},
		{"high weighted by confidence", Input{Detections: []Detection{{Name: "X", Severity: "High", Confidence: 80}}}, 36, "detection X: High", 36},
		{"medium", Input{Detections: []Detection{{Name: "X", Severity: "Medium", Confidence: 100}}}, 25, "detection X", 25},
		{"low", Input{Detections: []Detection{{Name: "X", Severity: "Low", Confidence: 100}}}, 10, "detection X", 10},
		{"info gives nothing", Input{Detections: []Detection{{Name: "X", Severity: "Info", Confidence: 100}}}, 0, "", 0},
		{"highest detection only", Input{Detections: []Detection{
			{Name: "A", Severity: "Low", Confidence: 100}, {Name: "B", Severity: "High", Confidence: 100}}}, 45, "detection B", 45},
		{"admin panel category", Input{Detections: []Detection{{Name: "P", Category: "admin-panel", Severity: "Info", Confidence: 90}}}, 20, "admin panel", 20},
		{"category counted once", Input{Detections: []Detection{
			{Name: "P1", Category: "admin-panel", Severity: "Info"}, {Name: "P2", Category: "admin-panel", Severity: "Info"}}}, 20, "admin panel", 20},
		{"staging", Input{Detections: []Detection{{Category: "staging", Severity: "Info"}}}, 15, "staging environment", 15},
		{"iot", Input{Detections: []Detection{{Category: "iot", Severity: "Info"}}}, 15, "IoT device", 15},
		{"cms", Input{Detections: []Detection{{Category: "cms", Severity: "Info"}}}, 5, "CMS", 5},
		{"outdated", Input{Detections: []Detection{{Severity: "Info", Outdated: "version 4.7 < 6.0"}}}, 15, "outdated version (version 4.7 < 6.0)", 15},
		{"telnet", Input{Port: 23, Service: "telnet"}, 30, "telnet (unencrypted)", 30},
		{"docker api by port", Input{Port: 2375, Service: "http"}, 40, "Docker API without TLS", 40},
		{"database by port", Input{Port: 3306}, 20, "database or cache reachable from the network", 20},
		{"postgres on non-standard port", Input{Port: 15432, Service: "postgresql"}, 20, "database or cache", 20},
		{"redis by name", Input{Port: 16379, Service: "redis"}, 20, "database or cache", 20},
		{"rdp", Input{Port: 3389, Service: "ms-wbt-server"}, 20, "remote desktop", 20},
		{"vnc", Input{Port: 5901, Service: "vnc"}, 20, "remote desktop", 20},
		{"ftp", Input{Port: 21, Service: "ftp"}, 15, "FTP", 15},
		{"amqp", Input{Port: 5672, Service: "amqp"}, 10, "message broker", 10},
		{"tls expired", Input{TLSExpired: true}, 10, "expired TLS certificate", 10},
		{"tls self-signed", Input{TLSSelfSigned: true}, 5, "self-signed TLS certificate", 5},
		{"login page over http", Input{Scheme: "http", Detections: login}, 10, "login without TLS", 10},
		{"login page over https", Input{Scheme: "https", Detections: login}, 0, "", 0},
		{"admin panel over http", Input{Scheme: "http", Detections: []Detection{{Category: "admin-panel", Severity: "Info"}}}, 30, "login without TLS", 10},
		{"new service", Input{ChangeKinds: []string{"new"}}, 15, "new service in this run", 15},
		{"changed service", Input{ChangeKinds: []string{"changed"}}, 5, "changed service", 5},
		{"unstable change", Input{ChangeKinds: []string{"unstable"}}, 5, "unstable host", 5},
		{"unstable host once", Input{ChangeKinds: []string{"unstable"}, HostUnstable: true}, 5, "unstable host", 5},
		{"analyst floor", Input{Port: 80, Service: "http", AnalystSeverity: "High"}, 70, "severity set by analyst", 70},
		{"analyst floor tops up", Input{TLSExpired: true, AnalystSeverity: "Medium"}, 40, "severity set by analyst", 30},
		{"analyst floor below score", Input{Port: 23, Service: "telnet", AnalystSeverity: "Low"}, 30, "telnet", 30},
		{"analyst critical", Input{AnalystSeverity: "Critical"}, 90, "severity set by analyst", 90},
		{"analyst info caps", Input{Port: 23, Service: "telnet", AnalystSeverity: "Info"}, 10, "telnet", 30},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := Score(tc.in)

			assert.Equal(t, tc.score, r.Score)
			if tc.reason == "" {
				assert.Len(t, 0, r.Reasons)
				return
			}
			assert.True(t, hasReason(r, tc.reason, tc.points))
		})
	}
}

func TestRedisNoAuthExample(t *testing.T) {
	in := Input{Port: 6379, Service: "redis", Detections: []Detection{
		{Signature: "redis-noauth", Name: "Redis without authentication", Category: "other", Severity: "High", Confidence: 85}}}

	r := Score(in)

	assert.Equal(t, 58, r.Score)
	assert.Equal(t, []Reason{
		{"detection Redis without authentication: High", 38},
		{"database or cache reachable from the network", 20},
	}, r.Reasons)
}

func TestCappedAt100(t *testing.T) {
	in := Input{Port: 2375, Service: "docker", Scheme: "http", TLSExpired: true,
		Detections:  []Detection{{Name: "X", Category: "admin-panel", Severity: "Critical", Confidence: 100, Outdated: "old"}},
		ChangeKinds: []string{"new"}}

	r := Score(in)

	assert.Equal(t, 100, r.Score)
	assert.Equal(t, "high", r.Priority)
}

func TestOnlyHighestServiceClass(t *testing.T) {
	r := Score(Input{Port: 2375, Service: "redis"})

	assert.Equal(t, 20, r.Score)
	assert.Len(t, 1, r.Reasons)
}

func TestFalsePositive(t *testing.T) {
	in := Input{Port: 2375, Service: "docker", AnalystSeverity: "Critical", FalsePositive: true,
		Detections: []Detection{{Name: "X", Severity: "Critical", Confidence: 100}}}

	r := Score(in)

	assert.Equal(t, 0, r.Score)
	assert.Equal(t, "low", r.Priority)
	assert.Equal(t, []Reason{{"marked as false positive", 0}}, r.Reasons)
}

func TestPriority(t *testing.T) {
	want := map[int]string{0: "low", 1: "low", 29: "low", 30: "medium", 59: "medium", 60: "high", 100: "high"}
	for score, p := range want {
		assert.Equal(t, p, priority(score))
	}
}

func TestScore_reasonOrderStable(t *testing.T) {
	in := Input{Port: 21, Service: "ftp", TLSSelfSigned: true, ChangeKinds: []string{"changed", "new"}, HostUnstable: true,
		Detections: []Detection{{Name: "W", Category: "cms", Severity: "High", Confidence: 100, Outdated: "v1 < v2"}}}

	first := Score(in)

	for i := 0; i < 20; i++ {
		assert.Equal(t, first, Score(in))
	}
	for i := 1; i < len(first.Reasons); i++ {
		assert.True(t, first.Reasons[i].Points <= first.Reasons[i-1].Points)
	}
	var order []string
	for _, r := range first.Reasons {
		if r.Points == 15 {
			order = append(order, r.Rule)
		}
	}
	assert.Equal(t, []string{"outdated version (v1 < v2)", "FTP", "new service in this run"}, order)
}

func TestScore_ranking(t *testing.T) {
	wordpress := Score(Input{Port: 80, Service: "http", Scheme: "http", Detections: []Detection{
		{Signature: "wordpress", Name: "WordPress", Category: "cms", Severity: "High", Confidence: 90, Outdated: "version 4.7 < 6.0"},
		{Signature: "wp-admin", Name: "WordPress admin", Category: "admin-panel", Severity: "Medium", Confidence: 80}}})
	redis := Score(Input{Port: 6379, Service: "redis", Detections: []Detection{
		{Signature: "redis-noauth", Name: "Redis without authentication", Category: "other", Severity: "High", Confidence: 60}}})
	nginx := Score(Input{Port: 80, Service: "http", Scheme: "http", Detections: []Detection{
		{Signature: "nginx", Name: "nginx", Category: "server", Severity: "Info", Confidence: 85}}})

	assert.True(t, wordpress.Score > redis.Score)
	assert.True(t, redis.Score > nginx.Score)
	assert.Equal(t, "low", nginx.Priority)
}

func TestExposedDatabase(t *testing.T) {
	assert.True(t, ExposedDatabase("redis", 6379))
	assert.True(t, ExposedDatabase("postgresql", 15432))
	assert.True(t, ExposedDatabase("http", 9200))
	assert.False(t, ExposedDatabase("ssh", 22))
	assert.False(t, ExposedDatabase("telnet", 23))
}
