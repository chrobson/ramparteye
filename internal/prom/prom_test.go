package prom

import (
	"math"
	"strings"
	"testing"

	"github.com/ctx42/testing/pkg/assert"
)

func encode(t *testing.T, fams ...Family) string {
	t.Helper()
	var b strings.Builder
	assert.NoError(t, Write(&b, fams))
	return b.String()
}

func TestWriteGauge(t *testing.T) {
	got := encode(t, Family{Name: "app_hosts", Help: "Hosts by state.", Type: Gauge, Samples: []Sample{
		{Labels: []Label{{"state", "up"}}, Value: 3},
		{Labels: []Label{{"state", "down"}}, Value: 0},
	}})

	want := "# HELP app_hosts Hosts by state.\n" +
		"# TYPE app_hosts gauge\n" +
		`app_hosts{state="up"} 3` + "\n" +
		`app_hosts{state="down"} 0` + "\n"
	assert.Equal(t, want, got)
}

func TestWriteCounterWithoutLabels(t *testing.T) {
	got := encode(t, Family{Name: "app_events_total", Help: "Events.", Type: Counter,
		Samples: []Sample{{Value: 12}}})

	assert.Equal(t, "# HELP app_events_total Events.\n# TYPE app_events_total counter\napp_events_total 12\n", got)
}

func TestWriteSeveralLabelsAndFamilies(t *testing.T) {
	got := encode(t,
		Family{Name: "a_info", Help: "A.", Type: Gauge, Samples: []Sample{
			{Labels: []Label{{"version", "v0.2.0"}, {"kind", "x"}}, Value: 1}}},
		Family{Name: "b", Help: "B.", Type: Gauge, Samples: []Sample{{Value: 2}}})

	want := "# HELP a_info A.\n# TYPE a_info gauge\n" + `a_info{version="v0.2.0",kind="x"} 1` + "\n" +
		"# HELP b B.\n# TYPE b gauge\nb 2\n"
	assert.Equal(t, want, got)
}

func TestWriteEscapesLabelValues(t *testing.T) {
	got := encode(t, Family{Name: "m", Help: "h", Type: Gauge, Samples: []Sample{
		{Labels: []Label{{"v", "a\\b\"c\nd"}}, Value: 1}}})

	assert.Contain(t, `m{v="a\\b\"c\nd"} 1`+"\n", got)
}

func TestWriteKeepsOtherLabelValueCharactersLiteral(t *testing.T) {
	got := encode(t, Family{Name: "m", Help: "h", Type: Gauge, Samples: []Sample{
		{Labels: []Label{{"v", "żółć {}=, #\t"}}, Value: 1}}})

	assert.Contain(t, "m{v=\"żółć {}=, #\t\"} 1\n", got)
}

func TestWriteEscapesHelp(t *testing.T) {
	got := encode(t, Family{Name: "m", Help: "line one\nline \\ two \"quoted\"", Type: Gauge,
		Samples: []Sample{{Value: 1}}})

	// HELP escapes the backslash and the line feed, not the double quote.
	assert.Contain(t, "# HELP m line one\\nline \\\\ two \"quoted\"\n", got)
	assert.Equal(t, 3, strings.Count(got, "\n"))
}

func TestWriteValues(t *testing.T) {
	tests := []struct {
		v    float64
		want string
	}{
		{0, "0"},
		{1, "1"},
		{-4, "-4"},
		{1234567, "1234567"},
		{1.7e9, "1700000000"},
		{1764244800, "1764244800"},
		{0.5, "0.5"},
		{12.345, "12.345"},
		{1e21, "1e+21"},
		{math.Inf(1), "+Inf"},
		{math.Inf(-1), "-Inf"},
		{math.NaN(), "NaN"},
		{math.Copysign(0, -1), "-0"},
	}
	for _, tc := range tests {
		got := encode(t, Family{Name: "m", Help: "h", Type: Gauge, Samples: []Sample{{Value: tc.v}}})

		assert.Contain(t, "\nm "+tc.want+"\n", got, "%v", tc.v)
	}
}

func TestWriteSkipsFamilyWithoutSamples(t *testing.T) {
	got := encode(t,
		Family{Name: "empty", Help: "h", Type: Gauge},
		Family{Name: "full", Help: "h", Type: Gauge, Samples: []Sample{{Value: 1}}})

	assert.NotContain(t, "empty", got)
	assert.Contain(t, "full 1\n", got)
}

func TestWriteNothing(t *testing.T) {
	assert.Equal(t, "", encode(t))
}

func TestWriteRejectsInvalid(t *testing.T) {
	ok := Sample{Value: 1}
	tests := map[string]Family{
		"empty name":        {Name: "", Help: "h", Type: Gauge, Samples: []Sample{ok}},
		"name with dash":    {Name: "a-b", Help: "h", Type: Gauge, Samples: []Sample{ok}},
		"name with digit":   {Name: "1a", Help: "h", Type: Gauge, Samples: []Sample{ok}},
		"name with space":   {Name: "a b", Help: "h", Type: Gauge, Samples: []Sample{ok}},
		"unknown type":      {Name: "a", Help: "h", Type: "histogram", Samples: []Sample{ok}},
		"empty help":        {Name: "a", Help: "", Type: Gauge, Samples: []Sample{ok}},
		"label with dash":   {Name: "a", Help: "h", Type: Gauge, Samples: []Sample{{Labels: []Label{{"a-b", "x"}}}}},
		"label with colon":  {Name: "a", Help: "h", Type: Gauge, Samples: []Sample{{Labels: []Label{{"a:b", "x"}}}}},
		"reserved label":    {Name: "a", Help: "h", Type: Gauge, Samples: []Sample{{Labels: []Label{{"__x", "x"}}}}},
		"empty label name":  {Name: "a", Help: "h", Type: Gauge, Samples: []Sample{{Labels: []Label{{"", "x"}}}}},
		"repeated label":    {Name: "a", Help: "h", Type: Gauge, Samples: []Sample{{Labels: []Label{{"x", "1"}, {"x", "2"}}}}},
		"duplicate series":  {Name: "a", Help: "h", Type: Gauge, Samples: []Sample{{Labels: []Label{{"x", "1"}}}, {Labels: []Label{{"x", "1"}}}}},
		"invalid utf8 text": {Name: "a", Help: "h", Type: Gauge, Samples: []Sample{{Labels: []Label{{"x", "\xff"}}}}},
	}
	for name, f := range tests {
		t.Run(name, func(t *testing.T) {
			var b strings.Builder

			err := Write(&b, []Family{f})

			assert.Error(t, err)
			assert.Equal(t, "", b.String(), "nothing is written on error")
		})
	}
}

func TestWriteRejectsDuplicateFamily(t *testing.T) {
	f := Family{Name: "a", Help: "h", Type: Gauge, Samples: []Sample{{Value: 1}}}
	var b strings.Builder

	err := Write(&b, []Family{f, f})

	assert.ErrorContain(t, "duplicate", err)
}

func TestContentType(t *testing.T) {
	assert.Equal(t, "text/plain; version=0.0.4; charset=utf-8", ContentType)
}
