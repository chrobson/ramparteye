package dojo

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
)

// Keys RampartEye emits. Every one of them is in the allowed set of DefectDojo's
// generic JSON parser (title/severity/description are its required keys;
// endpoints and tags are popped before the allowed-keys check).
var allowedFindingKeys = map[string]bool{
	"title":               true,
	"severity":            true,
	"description":         true,
	"steps_to_reproduce":  true,
	"cwe":                 true,
	"mitigation":          true,
	"references":          true,
	"date":                true,
	"unique_id_from_tool": true,
	"vuln_id_from_tool":   true,
	"endpoints":           true,
	"tags":                true,
}

// Subset of DefectDojo Endpoint model fields accepted inside "endpoints".
var allowedEndpointKeys = map[string]bool{
	"host":     true,
	"port":     true,
	"protocol": true,
	"path":     true,
}

// maxIDLen is the max_length of unique_id_from_tool / vuln_id_from_tool in
// the DefectDojo Finding model.
const maxIDLen = 500

var (
	dateRe     = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)
	protocolRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9.+-]*$`)
)

// Validate checks a Generic Findings file offline against the strict RampartEye
// whitelist: only the "findings" top-level key, only whitelisted finding and
// endpoint keys, required non-empty title/severity/description, a DefectDojo
// severity, YYYY-MM-DD dates, ports 1-65535 and a unique_id_from_tool that
// is present and unique within the file. All problems are reported at once.
func Validate(b []byte) error {
	var errs []error
	add := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }

	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var top map[string]json.RawMessage
	if err := dec.Decode(&top); err != nil {
		return fmt.Errorf("not a JSON object: %w", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("trailing data after the JSON object")
	}
	for k := range top {
		if k != "findings" {
			add("top-level key %q is not allowed", k)
		}
	}
	raw, ok := top["findings"]
	if !ok {
		add(`missing top-level key "findings"`)
		return errors.Join(errs...)
	}
	var findings []map[string]json.RawMessage
	if err := json.Unmarshal(raw, &findings); err != nil {
		add(`"findings" must be an array of objects: %v`, err)
		return errors.Join(errs...)
	}

	seen := map[string]int{}
	for i, f := range findings {
		for _, k := range sortedKeys(f) {
			if !allowedFindingKeys[k] {
				add("finding %d: key %q is not allowed", i, k)
			}
		}
		for _, k := range []string{"title", "severity", "description"} {
			s, err := stringField(f, k)
			if err != nil {
				add("finding %d: %v", i, err)
			} else if strings.TrimSpace(s) == "" {
				add("finding %d: required field %q is missing or empty", i, k)
			}
		}
		if s, err := stringField(f, "title"); err == nil && len(s) > maxTitleLen {
			add("finding %d: title longer than %d bytes", i, maxTitleLen)
		}
		if s, err := stringField(f, "severity"); err == nil && s != "" && !validSeverity(s) {
			add("finding %d: severity %q must be one of Info, Low, Medium, High, Critical", i, s)
		}
		if _, present := f["date"]; present {
			s, err := stringField(f, "date")
			if err != nil || !dateRe.MatchString(s) {
				add("finding %d: date must be YYYY-MM-DD", i)
			}
		}
		uid, err := stringField(f, "unique_id_from_tool")
		switch {
		case err != nil:
			add("finding %d: %v", i, err)
		case uid == "":
			add("finding %d: unique_id_from_tool is required", i)
		case len(uid) > maxIDLen:
			add("finding %d: unique_id_from_tool longer than %d", i, maxIDLen)
		default:
			if prev, dup := seen[uid]; dup {
				add("finding %d: duplicate unique_id_from_tool %q (also finding %d)", i, uid, prev)
			} else {
				seen[uid] = i
			}
		}
		if v, err := stringField(f, "vuln_id_from_tool"); err != nil {
			add("finding %d: %v", i, err)
		} else if len(v) > maxIDLen {
			add("finding %d: vuln_id_from_tool longer than %d", i, maxIDLen)
		}
		if c, ok := f["cwe"]; ok {
			var n json.Number
			d := json.NewDecoder(bytes.NewReader(c))
			d.UseNumber()
			if err := d.Decode(&n); err != nil {
				add("finding %d: cwe must be an integer", i)
			} else if v, err := n.Int64(); err != nil || v < 0 {
				add("finding %d: cwe must be a non-negative integer", i)
			}
		}
		for _, k := range []string{"mitigation", "references", "steps_to_reproduce"} {
			if _, err := stringField(f, k); err != nil {
				add("finding %d: %v", i, err)
			}
		}
		if t, ok := f["tags"]; ok {
			var tags []string
			if err := json.Unmarshal(t, &tags); err != nil {
				add("finding %d: tags must be an array of strings", i)
			}
		}
		if e, ok := f["endpoints"]; ok {
			validateEndpoints(i, e, add)
		}
	}
	return errors.Join(errs...)
}

func validateEndpoints(i int, raw json.RawMessage, add func(string, ...any)) {
	var eps []map[string]json.RawMessage
	if err := json.Unmarshal(raw, &eps); err != nil {
		add("finding %d: endpoints must be an array of objects", i)
		return
	}
	for j, e := range eps {
		for _, k := range sortedKeys(e) {
			if !allowedEndpointKeys[k] {
				add("finding %d endpoint %d: key %q is not allowed", i, j, k)
			}
		}
		if h, err := stringField(e, "host"); err != nil || strings.TrimSpace(h) == "" {
			add("finding %d endpoint %d: host is required", i, j)
		}
		if p, ok := e["port"]; ok {
			var n json.Number
			d := json.NewDecoder(bytes.NewReader(p))
			d.UseNumber()
			if err := d.Decode(&n); err != nil {
				add("finding %d endpoint %d: port must be a number", i, j)
			} else if v, err := n.Int64(); err != nil || v < 1 || v > 65535 {
				add("finding %d endpoint %d: port %s out of range 1-65535", i, j, n)
			}
		}
		if _, ok := e["protocol"]; ok {
			s, err := stringField(e, "protocol")
			if err != nil || !protocolRe.MatchString(s) {
				add("finding %d endpoint %d: invalid protocol", i, j)
			}
		}
		if _, err := stringField(e, "path"); err != nil {
			add("finding %d endpoint %d: %v", i, j, err)
		}
	}
}

// stringField returns the string value of key k ("" when absent) or an
// error when the value is not a JSON string.
func stringField(m map[string]json.RawMessage, k string) (string, error) {
	raw, ok := m[k]
	if !ok {
		return "", nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", fmt.Errorf("%q must be a string", k)
	}
	return s, nil
}

func sortedKeys(m map[string]json.RawMessage) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}
