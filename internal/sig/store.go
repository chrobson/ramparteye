package sig

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/chrobson/ramparteye/internal/model"
	"github.com/chrobson/ramparteye/internal/store"
)

// Lister reads the signatures table.
type Lister interface {
	Signatures(ctx context.Context) ([]store.SignatureRow, error)
}

// Store is the part of *store.Store the signature adapter uses.
type Store interface {
	Lister
	Signature(ctx context.Context, id string) (store.SignatureRow, error)
	SyncBuiltinSignatures(ctx context.Context, rows []store.SignatureRow) ([]string, error)
	CreateCustomSignature(ctx context.Context, row store.SignatureRow) error
	UpdateCustomSignature(ctx context.Context, id string, row store.SignatureRow) error
	SetSignatureEnabled(ctx context.Context, id string, enabled bool) error
	DeleteCustomSignature(ctx context.Context, id string) error
}

var _ Store = (*store.Store)(nil)

// Row converts a signature into a signatures table row.
func Row(s *Signature) store.SignatureRow {
	return store.SignatureRow{
		ID: s.ID, Name: s.Name, YAML: s.Raw,
		Enabled: s.Enabled, Source: s.Source, PathProbe: s.PathProbe,
	}
}

// SyncBuiltin makes the built-in rows of the signatures table match the
// embedded set (call once at startup, after migrations). A custom signature
// that holds the id of a built-in keeps it; each such collision is logged
// as a warning on log (nil = slog.Default()).
func SyncBuiltin(ctx context.Context, st interface {
	SyncBuiltinSignatures(ctx context.Context, rows []store.SignatureRow) ([]string, error)
}, log *slog.Logger) error {
	sigs, err := Builtin()
	if err != nil {
		return err
	}
	rows := make([]store.SignatureRow, 0, len(sigs))
	for _, s := range sigs {
		rows = append(rows, Row(s))
	}
	collisions, err := st.SyncBuiltinSignatures(ctx, rows)
	if log == nil {
		log = slog.Default()
	}
	for _, id := range collisions {
		log.Warn("custom signature shadows a built-in signature; the built-in is not loaded", "id", id)
	}
	return err
}

// LoadEnabled parses every enabled signature from the database, keeping
// the stored source and path probe flag. Rows that no longer validate are
// skipped and reported in the joined error, so one bad row never disables
// the others.
func LoadEnabled(ctx context.Context, st Lister) ([]*Signature, error) {
	rows, err := st.Signatures(ctx)
	if err != nil {
		return nil, err
	}
	var out []*Signature
	var errs []error
	for _, r := range rows {
		if !r.Enabled {
			continue
		}
		s, err := Parse([]byte(r.YAML))
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", r.ID, err))
			continue
		}
		s.Source = r.Source
		s.PathProbe = s.PathProbe || r.PathProbe
		out = append(out, s)
	}
	return out, errors.Join(errs...)
}

// Metas returns the classification (CWE, ATT&CK, remediation, references)
// of every signature, enabled or not, keyed by id, so a detection from an
// older run still gets it after its signature was disabled. Built-in
// signatures come from the embedded copy; stored rows that no longer parse
// are skipped. st may be nil (built-ins only).
func Metas(ctx context.Context, st Lister) map[string]model.SignatureMeta {
	out := map[string]model.SignatureMeta{}
	if builtin, err := Builtin(); err == nil {
		for _, s := range builtin {
			if m := s.Meta(); m != nil {
				out[s.ID] = *m
			}
		}
	}
	if st == nil {
		return out
	}
	rows, err := st.Signatures(ctx)
	if err != nil {
		return out
	}
	for _, r := range rows {
		if r.IsBuiltin() {
			continue // the embedded copy is current even before SyncBuiltin ran
		}
		s, err := Parse([]byte(r.YAML))
		if err != nil {
			continue
		}
		if m := s.Meta(); m != nil {
			out[s.ID] = *m
		} else {
			delete(out, s.ID)
		}
	}
	return out
}

// DBStore manages custom and nuclei signatures in the signatures table.
// Writes take parsed signatures, so only validated YAML is ever stored.
type DBStore struct {
	st Store
}

// NewDBStore returns a DBStore over st (usually *store.Store).
func NewDBStore(st Store) *DBStore { return &DBStore{st: st} }

// Get returns one stored signature row.
func (d *DBStore) Get(ctx context.Context, id string) (store.SignatureRow, error) {
	return d.st.Signature(ctx, id)
}

// Create validates s and stores it as a custom (or nuclei) signature.
func (d *DBStore) Create(ctx context.Context, s *Signature) error {
	row, err := customRow(s)
	if err != nil {
		return err
	}
	return d.st.CreateCustomSignature(ctx, row)
}

// Update validates s and replaces the stored custom signature id.
func (d *DBStore) Update(ctx context.Context, id string, s *Signature) error {
	row, err := customRow(s)
	if err != nil {
		return err
	}
	return d.st.UpdateCustomSignature(ctx, id, row)
}

// SetEnabled enables or disables a signature, built-ins included.
func (d *DBStore) SetEnabled(ctx context.Context, id string, enabled bool) error {
	return d.st.SetSignatureEnabled(ctx, id, enabled)
}

// Delete removes a custom or nuclei signature.
func (d *DBStore) Delete(ctx context.Context, id string) error {
	return d.st.DeleteCustomSignature(ctx, id)
}

// customRow re-parses s.Raw and converts the result into a non-built-in
// row, so the stored YAML is exactly what was validated. Source, Enabled and
// PathProbe come from s (Source empty = custom).
func customRow(s *Signature) (store.SignatureRow, error) {
	if s.Source == SourceBuiltin {
		return store.SignatureRow{}, fmt.Errorf("%w: %q", store.ErrSignatureBuiltin, s.ID)
	}
	parsed, err := Parse([]byte(s.Raw))
	if err != nil {
		return store.SignatureRow{}, err
	}
	parsed.Source = s.Source
	if parsed.Source == "" {
		parsed.Source = SourceCustom
	}
	parsed.Enabled = s.Enabled
	parsed.PathProbe = parsed.PathProbe || s.PathProbe
	return Row(parsed), nil
}
