package main

import (
	"encoding/json"
	"testing"

	"github.com/ctx42/testing/pkg/assert"
)

func TestScore(t *testing.T) {
	exp := map[string]bool{"a": true, "b": true, "c": true, "d": true}
	got := map[string]bool{"a": true, "b": true, "x": true}
	top := map[string]bool{"a": true, "b": true}

	m := score(exp, got, top)

	assert.Equal(t, 2, m.TP)
	assert.Equal(t, 1, m.FP)
	assert.Equal(t, 2, m.FN)
	assert.Equal(t, 0.667, m.Precision)
	assert.Equal(t, 0.5, m.Recall)
	assert.Equal(t, 1.0, *m.RecallTop1000)
	assert.Equal(t, []string{"c", "d"}, m.Missing)
	assert.Equal(t, []string{"x"}, m.Unexpected)

	e := score(map[string]bool{}, map[string]bool{}, nil)
	assert.Equal(t, 1.0, e.Precision)
	assert.Equal(t, 1.0, e.Recall)
	assert.Nil(t, e.RecallTop1000)
}

const labExpected = `{
  "run": "run2",
  "network": "10.20.0.0/18",
  "infra": [{"ip": "10.20.0.1"}],
  "hosts": [
    {"ip": "10.20.0.10", "name": "web", "services": [
      {"port": 80, "proto": "tcp", "in_top1000": true, "detections": ["staging-vhost"]},
      {"port": 25565, "proto": "tcp", "in_top1000": false, "detections": []}
    ]},
    {"ip": "10.20.0.20", "name": "cam", "services": [
      {"port": 80, "proto": "tcp", "in_top1000": true, "detections": ["ip-camera", "router-login"]}
    ]}
  ],
  "changes_from_prev": [
    {"kind": "new", "ip": "10.20.0.20", "port": 80, "proto": "tcp"},
    {"kind": "host_up", "ip": "10.20.0.20"}
  ]
}`

func loadLab(t *testing.T) expected {
	t.Helper()
	var e expected
	assert.NoError(t, json.Unmarshal([]byte(labExpected), &e))
	return e
}

func TestEvaluatePerfectRun(t *testing.T) {
	ms := int64(1200)
	obs := observed{
		RunID: 4, PrevRunID: 3, DurationMS: &ms,
		Hosts:    []string{"10.20.0.10", "10.20.0.20", "10.20.0.1", "192.168.1.1"}, // infra and outside dropped
		Services: []obsService{{"10.20.0.10", 80, "tcp"}, {"10.20.0.20", 80, "tcp"}, {"10.20.0.1", 53, "tcp"}},
		Detections: []obsDetection{
			{"10.20.0.10", 80, "staging-env"},
			{"10.20.0.20", 80, "iot-webui"}, // satisfies ip-camera and router-login
			{"10.20.0.10", 80, "nginx"},     // outside the lab vocabulary: not scored
		},
		Changes: []obsChange{{"new", "10.20.0.20", 80, "tcp"}, {"host_up", "10.20.0.20", 0, ""}},
	}

	rep := evaluate(loadLab(t), "lab/expected/run2.json", obs, 0.9)

	assert.True(t, rep.Pass)
	assert.Nil(t, rep.Failures)
	assert.Equal(t, int64(4), rep.RunID)
	assert.Equal(t, int64(3), rep.PrevRunID)
	assert.Equal(t, "lab/expected/run2.json", rep.Expected)
	assert.Equal(t, 1.0, rep.Hosts.Precision)
	assert.Equal(t, 1.0, rep.Hosts.Recall)
	assert.Equal(t, 1.0, rep.Services.Precision)
	assert.Equal(t, 0.667, rep.Services.Recall)
	assert.Equal(t, 1.0, *rep.Services.RecallTop1000)
	assert.Equal(t, []string{"10.20.0.10:25565/tcp"}, rep.Services.Missing)
	assert.Equal(t, 3, rep.Detections.TP)
	assert.Equal(t, 0, rep.Detections.FP)
	assert.Equal(t, 1.0, rep.Changes.Recall)
}

func TestEvaluateFailures(t *testing.T) {
	obs := observed{RunID: 5, PrevRunID: 4,
		Hosts:    []string{"10.20.0.10", "10.20.0.30"},
		Services: []obsService{{"10.20.0.10", 80, "tcp"}, {"10.20.0.30", 22, "tcp"}},
	}

	rep := evaluate(loadLab(t), "x.json", obs, 0.9)

	assert.False(t, rep.Pass)
	assert.Equal(t, []string{
		"hosts.precision = 0.500 < 0.90",
		"hosts.recall = 0.500 < 0.90",
		"services.precision = 0.500 < 0.90",
		"services.recall_top1000 = 0.500 < 0.90",
		"changes.recall_top1000 = 0.000 < 0.90",
	}, rep.Failures)
	assert.Equal(t, []string{"10.20.0.30:22/tcp"}, rep.Services.Unexpected)
}

func TestEvaluateFirstRunSkipsChanges(t *testing.T) {
	obs := observed{RunID: 1,
		Hosts:    []string{"10.20.0.10", "10.20.0.20"},
		Services: []obsService{{"10.20.0.10", 80, "tcp"}, {"10.20.0.20", 80, "tcp"}},
	}

	rep := evaluate(loadLab(t), "x.json", obs, 0.9)

	assert.True(t, rep.Pass)
}

func TestVerifyUsage(t *testing.T) {
	for name, tc := range map[string]struct {
		args []string
		want string
	}{
		"no file":   {nil, "usage: ramparteye verify <expected.json>"},
		"bad run":   {[]string{"x.json", "--run", "abc"}, "invalid value"},
		"bad min":   {[]string{"x.json", "--min", "2"}, "--min must be between 0 and 1"},
		"two files": {[]string{"a.json", "b.json"}, "usage: ramparteye verify <expected.json>"},
	} {
		t.Run(name, func(t *testing.T) {
			e, _, errb := testEnv(nil)

			code := e.run(append([]string{"ramparteye", "verify"}, tc.args...))

			assert.Equal(t, 2, code)
			assert.Contain(t, tc.want, errb.String())
		})
	}
}

func TestParseVerifyArgsFlagsAfterFile(t *testing.T) {
	a, err := parseVerifyArgs([]string{"lab/expected/run1.json", "--run", "7", "--min", "0.95"})

	assert.NoError(t, err)
	assert.Equal(t, verifyArgs{file: "lab/expected/run1.json", runID: 7, min: 0.95}, a)

	a, err = parseVerifyArgs([]string{"--run", "7", "lab/expected/run1.json"})
	assert.NoError(t, err)
	assert.Equal(t, verifyArgs{file: "lab/expected/run1.json", runID: 7, min: 0.9}, a)
}

func TestLoadExpected(t *testing.T) {
	e, err := loadExpected(writeFile(t, "run2.json", labExpected))
	assert.NoError(t, err)
	assert.Equal(t, "10.20.0.0/18", e.Network)
	assert.Len(t, 2, e.Hosts)

	_, err = loadExpected(writeFile(t, "bad.json", `{"network": "10.20.0.0/33"}`))
	assert.ErrorContain(t, `bad.json: invalid network "10.20.0.0/33"`, err)

	_, err = loadExpected(writeFile(t, "broken.json", `{`))
	assert.ErrorContain(t, "broken.json", err)
}
