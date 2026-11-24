package web

import (
	"bytes"
	"context"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/ctx42/testing/pkg/must"

	"github.com/chrobson/ramparteye/internal/diff"
	"github.com/chrobson/ramparteye/internal/dojo"
	"github.com/chrobson/ramparteye/internal/exchange"
	"github.com/chrobson/ramparteye/internal/model"
	"github.com/chrobson/ramparteye/internal/safety"
	"github.com/chrobson/ramparteye/internal/scope"
	"github.com/chrobson/ramparteye/internal/store"
)

// scanData is what the fake store returns for the scans, changes, targets
// and profile pages.
type scanData struct {
	configs    []store.ScanConfig
	nextCfg    int64
	deleteErr  error // returned by DeleteScanConfig
	receipts   map[int64]safety.Receipt
	changeRuns []store.ChangeRun
	series     []store.RunPoint
	nextTarget int64
}

func (f *fakeStore) ScanConfigs(context.Context) ([]store.ScanConfig, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.scans.configs), nil
}

func (f *fakeStore) ScanConfig(_ context.Context, id int64) (store.ScanConfig, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.scans.configs {
		if c.ID == id {
			return c, nil
		}
	}
	return store.ScanConfig{}, store.ErrScanConfigNotFound
}

func (f *fakeStore) CreateScanConfig(_ context.Context, c store.ScanConfig) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, o := range f.scans.configs {
		if o.Name == c.Name {
			return 0, store.ErrScanConfigNameTaken
		}
	}
	f.scans.nextCfg++
	c.ID = f.scans.nextCfg
	f.scans.configs = append(f.scans.configs, c)
	return c.ID, nil
}

func (f *fakeStore) UpdateScanConfig(_ context.Context, c store.ScanConfig) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i, o := range f.scans.configs {
		if o.ID == c.ID {
			f.scans.configs[i] = c
			return nil
		}
	}
	return store.ErrScanConfigNotFound
}

func (f *fakeStore) DeleteScanConfig(_ context.Context, id int64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.scans.deleteErr != nil {
		return f.scans.deleteErr
	}
	for i, o := range f.scans.configs {
		if o.ID == id {
			f.scans.configs = slices.Delete(f.scans.configs, i, i+1)
			return nil
		}
	}
	return store.ErrScanConfigNotFound
}

func (f *fakeStore) SafetyReceipt(_ context.Context, runID int64) (safety.Receipt, error) {
	if r, ok := f.scans.receipts[runID]; ok {
		return r, nil
	}
	return safety.Receipt{}, safety.ErrNoReceipt
}

func (f *fakeStore) ChangeRuns(context.Context, int) ([]store.ChangeRun, error) {
	return f.scans.changeRuns, nil
}

func (f *fakeStore) ChangeRun(_ context.Context, runID int64) (store.ChangeRun, error) {
	for _, r := range f.scans.changeRuns {
		if r.RunID == runID {
			return r, nil
		}
	}
	return store.ChangeRun{}, store.ErrRunNotFound
}

func (f *fakeStore) RunSeries(context.Context, int) ([]store.RunPoint, error) {
	return f.scans.series, nil
}

func (f *fakeStore) TargetTags(context.Context) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, t := range f.dash.targets {
		for _, tag := range t.Tags {
			if !slices.Contains(out, tag) {
				out = append(out, tag)
			}
		}
	}
	slices.Sort(out)
	return out, nil
}

func (f *fakeStore) InsertTargets(_ context.Context, ts []model.Target, _ *int64) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, t := range ts {
		if slices.ContainsFunc(f.dash.targets, func(o model.Target) bool { return o.Value == t.Value }) {
			continue
		}
		f.scans.nextTarget++
		t.ID = 100 + f.scans.nextTarget
		f.dash.targets = append(f.dash.targets, t)
		n++
	}
	return n, nil
}

func (f *fakeStore) UpdateTargetTags(_ context.Context, id int64, tags []string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i, t := range f.dash.targets {
		if t.ID == id {
			f.dash.targets[i].Tags = tags
			return nil
		}
	}
	return store.ErrTargetNotFound
}

func (f *fakeStore) DeleteTarget(_ context.Context, id int64) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i, t := range f.dash.targets {
		if t.ID == id {
			f.dash.targets = slices.Delete(f.dash.targets, i, i+1)
			return t.Value, nil
		}
	}
	return "", store.ErrTargetNotFound
}

func (f *fakeStore) targetValues() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, t := range f.dash.targets {
		out = append(out, t.Value)
	}
	return out
}

// fakeExchange records imports and returns fixed results.
type fakeExchange struct {
	rep       exchange.Report
	err       error
	imported  [][]byte
	snap      exchange.Snapshot
	snapErr   error
	snapAsked []int64
}

func (f *fakeExchange) Import(_ context.Context, b []byte, _ scope.Scope, _ diff.Config, _ time.Time) (exchange.Report, error) {
	f.imported = append(f.imported, b)
	return f.rep, f.err
}

func (f *fakeExchange) Snapshot(_ context.Context, runID int64) (exchange.Snapshot, error) {
	f.snapAsked = append(f.snapAsked, runID)
	if f.snap.RunID == 0 && f.snapErr == nil {
		return exchange.Snapshot{}, store.ErrRunNotFound
	}
	return f.snap, f.snapErr
}

func withExchange(x *fakeExchange) envOpt { return func(d *Deps) { d.Exchange = x } }

func withNoScope() envOpt { return func(d *Deps) { d.Scope = scope.Scope{} } }

// withResolver answers domain lookups from m; unknown names fail.
func withResolver(m map[string][]string) envOpt {
	return func(d *Deps) {
		d.Resolver = func(_ context.Context, host string) ([]netip.Addr, error) {
			var out []netip.Addr
			for _, a := range m[host] {
				out = append(out, netip.MustParseAddr(a))
			}
			return out, nil
		}
	}
}

// withPushResult makes PushRun return rec and err.
func (e *testEnv) withPushResult(rec dojo.PushRecord, err error) {
	e.pusher.pushRec, e.pusher.pushErr = rec, err
}

// upload sends a same-origin multipart POST with one file and extra fields.
func (e *testEnv) upload(path, field, name string, data []byte, fields map[string]string, c *http.Cookie) *httptest.ResponseRecorder {
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	for k, v := range fields {
		must.Nil(mw.WriteField(k, v))
	}
	fw := must.Value(mw.CreateFormFile(field, name))
	_, err := fw.Write(data)
	must.Nil(err)
	must.Nil(mw.Close())
	req := httptest.NewRequest(http.MethodPost, path, &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	if c != nil {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	return rec
}

// flashOf returns the flash message a redirect set.
func flashOf(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	for _, c := range rec.Result().Cookies() {
		if c.Name == flashCookie && c.MaxAge >= 0 {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.AddCookie(c)
			return takeFlash(httptest.NewRecorder(), req)
		}
	}
	return ""
}
