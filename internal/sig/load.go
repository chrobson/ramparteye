package sig

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"sort"

	"go.yaml.in/yaml/v3"

	"github.com/chrobson/ramparteye/internal/sig/builtin"
)

// Parse decodes and validates one signature document. Unknown fields are
// rejected, so request bodies, payloads or methods cannot be smuggled in
// under other names. The result is an enabled custom signature; callers
// loading from elsewhere set Source and Enabled.
func Parse(data []byte) (*Signature, error) {
	if len(data) > MaxYAMLBytes {
		return nil, fmt.Errorf("signature too large: %d bytes (max %d)", len(data), MaxYAMLBytes)
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var s Signature
	if err := dec.Decode(&s); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("empty signature")
		}
		return nil, fmt.Errorf("yaml: %w", err)
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, errors.New("one signature per document expected")
	}
	s.Raw = string(data)
	s.Source = SourceCustom
	s.Enabled = true
	if err := validate(&s); err != nil {
		return nil, err
	}
	s.PathProbe = s.hasPathMatcher()
	return &s, nil
}

// Load loads every *.yaml / *.yml file in the root of fsys. All errors are
// collected and returned joined, next to the signatures that did load.
// Duplicate IDs are errors.
func Load(fsys fs.FS) ([]*Signature, error) {
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		ext := path.Ext(e.Name())
		if !e.IsDir() && (ext == ".yaml" || ext == ".yml") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	var out []*Signature
	var errs []error
	seen := map[string]string{}
	for _, n := range names {
		b, err := fs.ReadFile(fsys, n)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", n, err))
			continue
		}
		s, err := Parse(b)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", n, err))
			continue
		}
		if prev, dup := seen[s.ID]; dup {
			errs = append(errs, fmt.Errorf("%s: duplicate id %q (also in %s)", n, s.ID, prev))
			continue
		}
		seen[s.ID] = n
		out = append(out, s)
	}
	return out, errors.Join(errs...)
}

// Builtin loads the signatures embedded from internal/sig/builtin.
func Builtin() ([]*Signature, error) {
	sigs, err := Load(builtin.FS)
	for _, s := range sigs {
		s.Source = SourceBuiltin
	}
	return sigs, err
}
