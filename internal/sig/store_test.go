package sig

import (
	"context"
	"errors"
	"testing"

	"github.com/ctx42/testing/pkg/assert"
	"github.com/ctx42/testing/pkg/must"

	"github.com/chrobson/ramparteye/internal/store"
)

// memStore is an in-memory signatures table with store.Store semantics.
type memStore struct {
	rows   []store.SignatureRow
	synced []store.SignatureRow
	err    error
}

func (m *memStore) Signatures(context.Context) ([]store.SignatureRow, error) {
	return append([]store.SignatureRow(nil), m.rows...), m.err
}

func (m *memStore) Signature(_ context.Context, id string) (store.SignatureRow, error) {
	for _, r := range m.rows {
		if r.ID == id {
			return r, nil
		}
	}
	return store.SignatureRow{}, store.ErrSignatureNotFound
}

func (m *memStore) SyncBuiltinSignatures(_ context.Context, rows []store.SignatureRow) error {
	m.synced = rows
	return m.err
}

func (m *memStore) CreateCustomSignature(_ context.Context, r store.SignatureRow) error {
	m.rows = append(m.rows, r)
	return m.err
}

func (m *memStore) UpdateCustomSignature(_ context.Context, id string, r store.SignatureRow) error {
	for i := range m.rows {
		if m.rows[i].ID == id {
			m.rows[i] = r
			return nil
		}
	}
	return store.ErrSignatureNotFound
}

func (m *memStore) SetSignatureEnabled(_ context.Context, id string, enabled bool) error {
	for i := range m.rows {
		if m.rows[i].ID == id {
			m.rows[i].Enabled = enabled
			return nil
		}
	}
	return store.ErrSignatureNotFound
}

func (m *memStore) DeleteCustomSignature(_ context.Context, id string) error {
	for i := range m.rows {
		if m.rows[i].ID == id {
			m.rows = append(m.rows[:i], m.rows[i+1:]...)
			return nil
		}
	}
	return store.ErrSignatureNotFound
}

const customDoc = "id: my-app\nname: My app\ncategory: other\nconfidence: 70\ncwe: [200]\nremediation: Fix it.\nmatchers:\n  - {type: title, regex: 'My App'}\n"

func TestSyncBuiltin(t *testing.T) {
	st := &memStore{}

	err := SyncBuiltin(context.Background(), st)

	assert.NoError(t, err)
	assert.Len(t, 41, st.synced)
	for _, r := range st.synced {
		assert.Equal(t, SourceBuiltin, r.Source, r.ID)
		assert.True(t, r.Enabled, r.ID)
		assert.NotEmpty(t, r.YAML, r.ID)
		if r.ID == "tomcat-manager" {
			assert.True(t, r.PathProbe)
		}
		if r.ID == "nginx" {
			assert.False(t, r.PathProbe)
		}
	}
}

func TestLoadEnabled(t *testing.T) {
	nginx := must.Value(Builtin())[0]
	st := &memStore{rows: []store.SignatureRow{
		Row(nginx),
		{ID: "my-app", Name: "My app", YAML: customDoc, Enabled: true, Source: SourceCustom},
		{ID: "off", Name: "Off", YAML: customDoc, Enabled: false, Source: SourceCustom},
		{ID: "broken", Name: "Broken", YAML: "id: broken\n", Enabled: true, Source: SourceNuclei},
	}}

	sigs, err := LoadEnabled(context.Background(), st)

	assert.ErrorContain(t, "broken", err)
	assert.Len(t, 2, sigs)
	assert.Equal(t, nginx.ID, sigs[0].ID)
	assert.Equal(t, SourceBuiltin, sigs[0].Source)
	assert.Equal(t, "my-app", sigs[1].ID)
	assert.Equal(t, SourceCustom, sigs[1].Source)
	assert.True(t, sigs[1].Enabled)
}

func TestLoadEnabledKeepsStoredPathProbe(t *testing.T) {
	st := &memStore{rows: []store.SignatureRow{{ID: "my-app", YAML: customDoc, Enabled: true, Source: SourceNuclei, PathProbe: true}}}

	sigs := must.Value(LoadEnabled(context.Background(), st))

	assert.True(t, sigs[0].PathProbe)
	assert.Equal(t, SourceNuclei, sigs[0].Source)
}

func TestLoadEnabledStoreError(t *testing.T) {
	st := &memStore{err: errors.New("db down")}

	_, err := LoadEnabled(context.Background(), st)

	assert.ErrorContain(t, "db down", err)
}

func TestMetas(t *testing.T) {
	st := &memStore{rows: []store.SignatureRow{
		{ID: "my-app", YAML: customDoc, Enabled: false, Source: SourceCustom},
		// A stale built-in row: the embedded copy wins.
		{ID: "redis-noauth", YAML: "id: redis-noauth\n", Source: SourceBuiltin},
	}}

	metas := Metas(context.Background(), st)

	assert.Equal(t, []int{200}, metas["my-app"].CWE)
	assert.Equal(t, "Fix it.", metas["my-app"].Remediation)
	assert.Equal(t, 306, metas["redis-noauth"].CWE[0])
	assert.HasKey(t, "wordpress", metas)
}

func TestMetasWithoutStore(t *testing.T) {
	metas := Metas(context.Background(), nil)

	assert.HasKey(t, "redis-noauth", metas)
}

func TestDBStoreCreateValidates(t *testing.T) {
	st := &memStore{}
	db := NewDBStore(st)
	s := mustParse(t, customDoc)

	assert.NoError(t, db.Create(context.Background(), s))
	assert.Len(t, 1, st.rows)
	assert.Equal(t, SourceCustom, st.rows[0].Source)
	assert.Equal(t, customDoc, st.rows[0].YAML)

	bad := &Signature{ID: "x"}
	assert.Error(t, db.Create(context.Background(), bad))
	assert.Len(t, 1, st.rows)
}

func TestDBStoreRefusesBuiltinSource(t *testing.T) {
	st := &memStore{}
	s := mustParse(t, customDoc)
	s.Source = SourceBuiltin

	err := NewDBStore(st).Create(context.Background(), s)

	assert.ErrorIs(t, store.ErrSignatureBuiltin, err)
	assert.Len(t, 0, st.rows)
}

func TestDBStoreUpdateSetEnabledDelete(t *testing.T) {
	st := &memStore{}
	db := NewDBStore(st)
	ctx := context.Background()
	s := mustParse(t, customDoc)
	assert.NoError(t, db.Create(ctx, s))

	s2 := mustParse(t, customDoc+"description: v2\n")
	assert.NoError(t, db.Update(ctx, "my-app", s2))
	assert.Contain(t, "v2", must.Value(db.Get(ctx, "my-app")).YAML)

	assert.NoError(t, db.SetEnabled(ctx, "my-app", false))
	assert.False(t, must.Value(db.List(ctx))[0].Enabled)

	assert.NoError(t, db.Delete(ctx, "my-app"))
	assert.Len(t, 0, st.rows)
}
