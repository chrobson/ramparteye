package target

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/chrobson/ramparteye/internal/model"
)

// Input limits shared by file upload and CLI import.
const (
	MaxImportBytes   = 5 << 20
	MaxImportEntries = 20000
)

var (
	// ErrTooBig is returned when an import input exceeds MaxImportBytes.
	ErrTooBig = fmt.Errorf("input too large (max %d bytes)", MaxImportBytes)
	// ErrTooManyEntries is returned when an input exceeds MaxImportEntries.
	ErrTooManyEntries = fmt.Errorf("too many entries (max %d)", MaxImportEntries)
)

// entry is one raw input record before validation.
type entry struct {
	line  int // 1-based source line, 0 if unknown
	value string
	tags  []string
	err   error // decode-level problem with this record
}

// ImportCSVLines reads "value,tags" rows (tags separated by ';'). A header
// row whose first cell is "value", blank lines and '#' comments are skipped.
// The first invalid row aborts the import with an error naming its line.
// Duplicate values are merged (tags are combined). It also returns, for every
// target, the source line of its first occurrence. Scope is not checked here:
// callers run Resolve on every returned target.
func ImportCSVLines(r io.Reader) ([]model.Target, []int, error) {
	data, err := readLimited(r)
	if err != nil {
		return nil, nil, err
	}
	es, err := parseCSV(data)
	if err != nil {
		return nil, nil, err
	}
	return build(es)
}

// ImportJSONLines reads [{"value": "...", "tags": ["a","b"]}]; tags may
// also be a single "a;b" string. Semantics otherwise match ImportCSVLines. It
// also returns, for every target, the source line where its first object
// starts.
func ImportJSONLines(r io.Reader) ([]model.Target, []int, error) {
	data, err := readLimited(r)
	if err != nil {
		return nil, nil, err
	}
	es, err := parseJSON(data)
	if err != nil {
		return nil, nil, err
	}
	return build(es)
}

func readLimited(r io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, MaxImportBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > MaxImportBytes {
		return nil, ErrTooBig
	}
	return bytes.TrimPrefix(data, []byte("\xef\xbb\xbf")), nil
}

func build(es []entry) ([]model.Target, []int, error) {
	var (
		out   []model.Target
		lines []int
	)
	index := map[string]int{}
	for _, e := range es {
		var tg model.Target
		err := e.err
		if err == nil {
			tg, err = Parse(e.value)
		}
		if err == nil {
			tg.Tags, err = NormalizeTags(e.tags)
		}
		if err != nil {
			return nil, nil, fmt.Errorf("line %d: %q: %w", e.line, truncate(e.value), err)
		}
		if i, ok := index[tg.Value]; ok {
			merged, err := NormalizeTags(append(out[i].Tags, tg.Tags...))
			if err != nil {
				return nil, nil, fmt.Errorf("line %d: %q: %w", e.line, truncate(e.value), err)
			}
			out[i].Tags = merged
			continue
		}
		index[tg.Value] = len(out)
		out = append(out, tg)
		lines = append(lines, e.line)
	}
	return out, lines, nil
}

func truncate(s string) string {
	if len(s) > 80 {
		return s[:80] + "..."
	}
	return s
}

func parseCSV(data []byte) ([]entry, error) {
	cr := csv.NewReader(bytes.NewReader(data))
	cr.FieldsPerRecord = -1
	cr.TrimLeadingSpace = true
	cr.Comment = '#'
	var out []entry
	first := true
	for {
		rec, err := cr.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("csv: %w", err)
		}
		line, _ := cr.FieldPos(0)
		if first {
			first = false
			if strings.EqualFold(strings.TrimSpace(rec[0]), "value") {
				continue
			}
		}
		if len(rec) == 1 && strings.TrimSpace(rec[0]) == "" {
			continue
		}
		e := entry{line: line, value: strings.TrimSpace(rec[0])}
		for _, cell := range rec[1:] {
			e.tags = append(e.tags, SplitTags(cell)...)
		}
		out = append(out, e)
		if len(out) > MaxImportEntries {
			return nil, ErrTooManyEntries
		}
	}
	return out, nil
}

type jsonEntry struct {
	Value string          `json:"value"`
	Tags  json.RawMessage `json:"tags"`
}

func parseJSON(data []byte) ([]entry, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	tok, err := dec.Token()
	if err != nil {
		return nil, fmt.Errorf("json: %w", err)
	}
	if d, ok := tok.(json.Delim); !ok || d != '[' {
		return nil, errors.New("json: expected an array of {value, tags} objects")
	}
	var out []entry
	for dec.More() {
		start := skipSep(data, int(dec.InputOffset()))
		line := 1 + bytes.Count(data[:start], []byte("\n"))
		var je jsonEntry
		if err := dec.Decode(&je); err != nil {
			return nil, fmt.Errorf("json (line %d): %w", line, err)
		}
		tags, err := decodeTags(je.Tags)
		out = append(out, entry{line: line, value: strings.TrimSpace(je.Value), tags: tags, err: err})
		if len(out) > MaxImportEntries {
			return nil, ErrTooManyEntries
		}
	}
	if _, err := dec.Token(); err != nil {
		return nil, fmt.Errorf("json: %w", err)
	}
	return out, nil
}

func decodeTags(raw json.RawMessage) ([]string, error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	var list []string
	if err := json.Unmarshal(raw, &list); err == nil {
		return list, nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return SplitTags(s), nil
	}
	return nil, errors.New("tags must be a list of strings")
}

func skipSep(data []byte, i int) int {
	for i < len(data) {
		switch data[i] {
		case ' ', '\t', '\r', '\n', ',':
			i++
		default:
			return i
		}
	}
	return i
}
