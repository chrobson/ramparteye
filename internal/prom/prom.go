// Package prom writes metrics in the Prometheus text exposition format,
// version 0.0.4. It covers what RampartEye exposes (gauges and counters
// with labels) and nothing else, so no client library is needed.
package prom

import (
	"bytes"
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"
	"unicode/utf8"
)

// ContentType is the Content-Type of the text exposition format 0.0.4.
const ContentType = "text/plain; version=0.0.4; charset=utf-8"

// Type is the metric type of a family.
type Type string

// Metric types.
const (
	Gauge   Type = "gauge"
	Counter Type = "counter"
)

// Label is one label of a sample. Label values come from fixed
// enumerations in the code, never from scanned content.
type Label struct{ Name, Value string }

// Sample is one time series of a family.
type Sample struct {
	Labels []Label
	Value  float64
}

// Family is a metric with its help text, type and samples.
type Family struct {
	Name    string
	Help    string
	Type    Type
	Samples []Sample
}

// Write encodes fams to w, one HELP and TYPE header per family followed by
// its samples, in the given order. A family without samples is left out.
// The whole output is built first: on an error nothing is written. Invalid
// names, a repeated family, a repeated series and text that is not UTF-8
// are errors, since a scraper would reject the whole response.
func Write(w io.Writer, fams []Family) error {
	var b bytes.Buffer
	seen := map[string]bool{}
	for _, f := range fams {
		if err := checkFamily(f); err != nil {
			return err
		}
		if seen[f.Name] {
			return fmt.Errorf("prom: duplicate family %s", f.Name)
		}
		seen[f.Name] = true
		if len(f.Samples) == 0 {
			continue
		}
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s %s\n", f.Name, helpEscaper.Replace(f.Help), f.Name, f.Type)
		series := map[string]bool{}
		for _, s := range f.Samples {
			labels, err := labelSet(f.Name, s.Labels)
			if err != nil {
				return err
			}
			if series[labels] {
				return fmt.Errorf("prom: %s: duplicate series %s%s", f.Name, f.Name, labels)
			}
			series[labels] = true
			b.WriteString(f.Name)
			b.WriteString(labels)
			b.WriteByte(' ')
			b.WriteString(formatValue(s.Value))
			b.WriteByte('\n')
		}
	}
	_, err := w.Write(b.Bytes())
	return err
}

func checkFamily(f Family) error {
	if !validName(f.Name, true) {
		return fmt.Errorf("prom: invalid metric name %q", f.Name)
	}
	if f.Type != Gauge && f.Type != Counter {
		return fmt.Errorf("prom: %s: unknown type %q", f.Name, f.Type)
	}
	if f.Help == "" || !utf8.ValidString(f.Help) {
		return fmt.Errorf("prom: %s: help must be non-empty UTF-8", f.Name)
	}
	return nil
}

// labelSet renders labels as {a="x",b="y"} ("" without labels), which also
// identifies the series within its family.
func labelSet(family string, labels []Label) (string, error) {
	if len(labels) == 0 {
		return "", nil
	}
	var b strings.Builder
	names := map[string]bool{}
	b.WriteByte('{')
	for i, l := range labels {
		if !validName(l.Name, false) || strings.HasPrefix(l.Name, "__") {
			return "", fmt.Errorf("prom: %s: invalid label name %q", family, l.Name)
		}
		if names[l.Name] {
			return "", fmt.Errorf("prom: %s: label %s repeated", family, l.Name)
		}
		names[l.Name] = true
		if !utf8.ValidString(l.Value) {
			return "", fmt.Errorf("prom: %s: label %s is not valid UTF-8", family, l.Name)
		}
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(l.Name)
		b.WriteString(`="`)
		b.WriteString(labelEscaper.Replace(l.Value))
		b.WriteByte('"')
	}
	b.WriteByte('}')
	return b.String(), nil
}

// validName reports whether s is a metric name (colon allowed) or a label
// name: [a-zA-Z_:][a-zA-Z0-9_:]* and [a-zA-Z_][a-zA-Z0-9_]*.
func validName(s string, colon bool) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c == '_':
		case c == ':' && colon:
		case c >= '0' && c <= '9' && i > 0:
		default:
			return false
		}
	}
	return true
}

var (
	// HELP text escapes the backslash and the line feed.
	helpEscaper = strings.NewReplacer(`\`, `\\`, "\n", `\n`)
	// Label values escape the backslash, the double quote and the line feed.
	labelEscaper = strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)
)

// formatValue prints whole numbers without an exponent (timestamps and
// counts stay readable) and everything else in the shortest exact form.
func formatValue(v float64) string {
	switch {
	case math.IsNaN(v):
		return "NaN"
	case math.IsInf(v, 1):
		return "+Inf"
	case math.IsInf(v, -1):
		return "-Inf"
	case v == math.Trunc(v) && math.Abs(v) < 1e15:
		return strconv.FormatFloat(v, 'f', -1, 64)
	}
	return strconv.FormatFloat(v, 'g', -1, 64)
}
