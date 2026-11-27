package notify

import (
	"context"
	"net/netip"
	"sync"
	"time"

	"github.com/chrobson/ramparteye/internal/model"
	"github.com/chrobson/ramparteye/internal/safety"
	"github.com/chrobson/ramparteye/internal/store"
)

// memStore is an in-memory Store: one settings row, the delivery history
// and run results by id.
type memStore struct {
	mu         sync.Mutex
	cfg        *store.NotifyConfig // nil = missing row
	cfgErr     error
	saves      int
	deliveries []store.NotifyDelivery // oldest first
	runs       map[int64]*runData
	latest     int64
	panics     bool
}

func newMemStore() *memStore {
	return &memStore{cfg: &store.NotifyConfig{Format: FormatJSON, OnlyChanges: true}, runs: map[int64]*runData{}}
}

func (m *memStore) addRun(d *runData) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.runs[d.Run.ID] = d
	if d.Run.Status == store.RunDone {
		m.latest = max(m.latest, d.Run.ID)
	}
}

func (m *memStore) NotifyConfig(context.Context) (store.NotifyConfig, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cfgErr != nil {
		return store.NotifyConfig{}, m.cfgErr
	}
	if m.cfg == nil {
		return store.NotifyConfig{}, store.ErrNotFound
	}
	return *m.cfg, nil
}

func (m *memStore) SaveNotifyConfig(_ context.Context, c store.NotifyConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.saves++
	old := store.NotifyConfig{}
	if m.cfg != nil {
		old = *m.cfg
	}
	switch {
	case c.ClearURL:
		c.URLEnc, c.Endpoint = nil, ""
	case c.URLEnc == nil:
		c.URLEnc, c.Endpoint = old.URLEnc, old.Endpoint
	}
	switch {
	case c.ClearSecret:
		c.SecretEnc = nil
	case c.SecretEnc == nil:
		c.SecretEnc = old.SecretEnc
	}
	c.ClearURL, c.ClearSecret = false, false
	m.cfg = &c
	return nil
}

func (m *memStore) RecordNotifyDelivery(_ context.Context, d store.NotifyDelivery) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	d.ID = int64(len(m.deliveries) + 1)
	d.At = time.Now()
	m.deliveries = append(m.deliveries, d)
	return nil
}

func (m *memStore) NotifyDeliveries(_ context.Context, limit int) ([]store.NotifyDelivery, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []store.NotifyDelivery
	for i := len(m.deliveries) - 1; i >= 0 && len(out) < limit; i-- {
		out = append(out, m.deliveries[i])
	}
	return out, nil
}

func (m *memStore) history() []store.NotifyDelivery {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]store.NotifyDelivery(nil), m.deliveries...)
}

func (m *memStore) run(id int64) (*runData, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.panics {
		panic("boom")
	}
	d, ok := m.runs[id]
	if !ok {
		return nil, store.ErrRunNotFound
	}
	return d, nil
}

func (m *memStore) Run(_ context.Context, id int64) (store.RunSummary, error) {
	d, err := m.run(id)
	if err != nil {
		return store.RunSummary{}, err
	}
	return d.Run, nil
}

func (m *memStore) ChangeRun(_ context.Context, id int64) (store.ChangeRun, error) {
	d, err := m.run(id)
	if err != nil {
		return store.ChangeRun{}, err
	}
	return store.ChangeRun{RunID: id, PrevRunID: d.PrevRunID, Status: d.Run.Status}, nil
}

func (m *memStore) Changes(_ context.Context, id int64) ([]model.Change, error) {
	d, err := m.run(id)
	if err != nil {
		return nil, err
	}
	return d.Changes, nil
}

func (m *memStore) ExportServices(_ context.Context, id int64) ([]store.ExportService, error) {
	d, err := m.run(id)
	if err != nil {
		return nil, err
	}
	return d.Services, nil
}

func (m *memStore) SafetyReceipt(_ context.Context, id int64) (safety.Receipt, error) {
	d, err := m.run(id)
	if err != nil {
		return safety.Receipt{}, err
	}
	if d.Safety == nil {
		return safety.Receipt{}, safety.ErrNoReceipt
	}
	return safety.Receipt{RunID: id}, nil
}

func (m *memStore) HostStates(context.Context, model.HostStateKind) ([]model.HostState, error) {
	return nil, nil
}

func (m *memStore) AnnotationsByIPs(context.Context, []netip.Addr) (map[model.AssetKey]store.Annotation, error) {
	return map[model.AssetKey]store.Annotation{}, nil
}

func (m *memStore) LatestDoneRun(context.Context) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.latest, nil
}
