package dojo

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/ctx42/testing/pkg/assert"
	"github.com/ctx42/testing/pkg/must"

	"github.com/chrobson/ramparteye/internal/config"
	"github.com/chrobson/ramparteye/internal/model"
	"github.com/chrobson/ramparteye/internal/secret"
	"github.com/chrobson/ramparteye/internal/store"
)

// memPushStore is an in-memory PushStore serving one run snapshot.
type memPushStore struct {
	mu     sync.Mutex
	snap   store.DojoRun
	runErr error
	panics bool
	pushes []store.DojoPush // oldest first
}

func (m *memPushStore) DojoRun(_ context.Context, runID int64) (store.DojoRun, error) {
	if m.panics {
		panic("boom")
	}
	if m.runErr != nil {
		return store.DojoRun{}, m.runErr
	}
	if runID != 0 && runID != m.snap.Run.ID {
		return store.DojoRun{}, store.ErrRunNotFound
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.snap
	for i := len(m.pushes) - 1; i >= 0; i-- {
		if m.pushes[i].OK {
			n := m.pushes[i].Findings
			s.PrevFindings = &n
			break
		}
	}
	return s, nil
}

func (m *memPushStore) RecordDojoPush(_ context.Context, p store.DojoPush) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	p.ID = int64(len(m.pushes) + 1)
	p.At = time.Now()
	m.pushes = append(m.pushes, p)
	return nil
}

func (m *memPushStore) DojoPushes(_ context.Context, limit int) ([]store.DojoPush, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []store.DojoPush
	for i := len(m.pushes) - 1; i >= 0 && len(out) < limit; i-- {
		out = append(out, m.pushes[i])
	}
	return out, nil
}

func (m *memPushStore) Signatures(context.Context) ([]store.SignatureRow, error) { return nil, nil }

func (m *memPushStore) history() []store.DojoPush {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]store.DojoPush(nil), m.pushes...)
}

func pushSnap(profile string) store.DojoRun {
	fin := time.Date(2026, 11, 24, 10, 0, 0, 0, time.UTC)
	svc := func(ip string, port uint16) store.ExportService {
		return store.ExportService{ServiceObs: model.ServiceObs{
			Key: model.AssetKey{IP: netip.MustParseAddr(ip), Port: port, Proto: "tcp"}}}
	}
	web := svc("10.20.0.5", 443)
	web.Hostname = "web"
	web.HTTP = &store.HTTPSummary{URL: "https://10.20.0.5/", Status: 200, Title: "Panel"}
	web.Detections = []model.Detection{{SignatureID: "wp", Name: "WordPress", Category: "cms", Confidence: 90}}
	return store.DojoRun{
		Run:         store.ExportRun{ID: 7, Kind: "scan", Status: "done", FinishedAt: &fin},
		ProfileName: profile,
		Services:    []store.ExportService{svc("10.20.0.4", 22), web},
	}
}

// dedupDojo emulates DefectDojo reimport-scan: one test per test_title in
// one engagement, findings matched by title and description. A finding
// whose hash already exists in another test of the engagement is counted
// as a duplicate.
type dedupDojo struct {
	mu         sync.Mutex
	tests      map[string]map[string]bool // test title -> finding hashes
	titles     []string
	duplicates int
	status     int           // non-zero: reply with this status
	block      chan struct{} // non-nil: wait for it (or the request ctx)
	inFlight   map[string]int
	maxFlight  int
	noStats    bool
}

func newDedupDojo(t *testing.T) (*dedupDojo, *httptest.Server) {
	t.Helper()
	d := &dedupDojo{tests: map[string]map[string]bool{}, inFlight: map[string]int{}}
	srv := httptest.NewServer(http.HandlerFunc(d.serve))
	t.Cleanup(srv.Close)
	return d, srv
}

func (d *dedupDojo) serve(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/api/v2/reimport-scan/" || r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	if r.Header.Get("Authorization") != "Token "+testToken {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"detail":"Invalid token `+r.Header.Get("Authorization")+`"}`)
		return
	}
	must.Nil(r.ParseMultipartForm(1 << 20))
	title := r.FormValue("test_title")
	d.mu.Lock()
	d.titles = append(d.titles, title)
	d.inFlight[title]++
	d.maxFlight = max(d.maxFlight, d.inFlight[title])
	status, block := d.status, d.block
	d.mu.Unlock()
	defer func() {
		d.mu.Lock()
		d.inFlight[title]--
		d.mu.Unlock()
	}()
	if block != nil {
		select {
		case <-block:
		case <-r.Context().Done():
			return
		}
	}
	if status != 0 {
		w.WriteHeader(status)
		_, _ = io.WriteString(w, `{"detail":"server error, token `+r.Header.Get("Authorization")+`"}`)
		return
	}
	file, _, err := r.FormFile("file")
	must.Nil(err)
	var doc struct {
		Findings []struct {
			Title       string `json:"title"`
			Description string `json:"description"`
		} `json:"findings"`
	}
	must.Nil(json.NewDecoder(file).Decode(&doc))

	d.mu.Lock()
	defer d.mu.Unlock()
	cur, ok := d.tests[title]
	if !ok {
		cur = map[string]bool{}
		d.tests[title] = cur
	}
	next := map[string]bool{}
	created := 0
	for _, f := range doc.Findings {
		h := f.Title + "\x00" + f.Description
		next[h] = true
		if cur[h] {
			continue
		}
		created++
		for other, hs := range d.tests {
			if other != title && hs[h] {
				d.duplicates++
			}
		}
	}
	closed := 0
	if r.FormValue("close_old_findings") == "true" {
		for h := range cur {
			if !next[h] {
				closed++
			}
		}
		d.tests[title] = next
	} else {
		for h := range next {
			cur[h] = true
		}
	}
	w.WriteHeader(http.StatusCreated)
	if d.noStats {
		_, _ = io.WriteString(w, `{"test_id":42}`)
		return
	}
	_, _ = fmt.Fprintf(w, `{"test_id":42,"engagement_id":3,"product_id":2,"statistics":{"delta":{`+
		`"created":{"total":{"active":%d,"total":%d}},"closed":{"total":{"total":%d}},`+
		`"reactivated":{"total":{"total":0}},"untouched":{"total":{"total":%d}}}}}`,
		created, created, closed, len(doc.Findings)-created)
}

func (d *dedupDojo) seenTitles() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.titles...)
}

func configured(url string) Settings {
	return Settings{URL: url, Token: testToken, TokenSet: true, ProductType: "RampartEye",
		Engagement: "Continuous discovery", AutoPush: true, CloseMissing: true}
}

func newTestPusher(st PushStore, s Settings) *Pusher {
	return NewPusher(st, func(context.Context) (Settings, error) { return s, nil }, DefaultClient)
}

func TestAutoPushAfterDone(t *testing.T) {
	fake, srv := newDedupDojo(t)
	st := &memPushStore{snap: pushSnap("dmz")}
	p := newTestPusher(st, configured(srv.URL))

	p.OnRunDone(context.Background(), 7, "done")
	p.Wait()

	pushes := st.history()
	assert.Len(t, 1, pushes)
	assert.True(t, pushes[0].OK)
	assert.Equal(t, "auto", pushes[0].Trigger)
	assert.Equal(t, "reimport-scan", pushes[0].Endpoint)
	assert.Equal(t, int64(7), *pushes[0].RunID)
	assert.Equal(t, int64(42), *pushes[0].TestID)
	assert.Equal(t, 3, pushes[0].Findings) // two services, one detection
	assert.Equal(t, 3, pushes[0].Added)
	assert.Equal(t, []string{"RampartEye – dmz"}, fake.seenTitles())
}

func TestAutoPushOnlyWhenDone(t *testing.T) {
	for _, status := range []string{"cancelled", "failed", "paused", "running", ""} {
		t.Run(status, func(t *testing.T) {
			fake, srv := newDedupDojo(t)
			st := &memPushStore{snap: pushSnap("dmz")}
			p := newTestPusher(st, configured(srv.URL))

			p.OnRunDone(context.Background(), 7, status)
			p.Wait()

			assert.Len(t, 0, st.history())
			assert.Len(t, 0, fake.seenTitles())
		})
	}
}

func TestAutoPushDisabled(t *testing.T) {
	fake, srv := newDedupDojo(t)
	st := &memPushStore{snap: pushSnap("dmz")}
	s := configured(srv.URL)
	s.AutoPush = false
	p := newTestPusher(st, s)

	p.OnRunDone(context.Background(), 7, "done")
	p.Wait()

	assert.Len(t, 0, st.history())
	assert.Len(t, 0, fake.seenTitles())

	// A manual push still works.
	rec, err := p.PushRun(context.Background(), 7, "manual")
	assert.NoError(t, err)
	assert.True(t, rec.OK)
	assert.Equal(t, "manual", rec.Trigger)
}

func TestNoPushWhenNotConfigured(t *testing.T) {
	cases := map[string]Settings{
		"no url":   {Token: testToken, TokenSet: true, AutoPush: true},
		"no token": {URL: "http://127.0.0.1:1", AutoPush: true},
		"empty":    {AutoPush: true},
	}
	for name, s := range cases {
		t.Run(name, func(t *testing.T) {
			st := &memPushStore{snap: pushSnap("dmz")}
			p := newTestPusher(st, s)

			p.OnRunDone(context.Background(), 7, "done")
			p.Wait()
			_, err := p.PushRun(context.Background(), 7, "manual")

			assert.ErrorIs(t, ErrNotConfigured, err)
			assert.Len(t, 0, st.history())
			chip := must.Value(p.Status(context.Background()))
			assert.False(t, chip.Configured)
			assert.Nil(t, chip.LastOK)
		})
	}
}

func TestPushFailureRecordedScanUnaffected(t *testing.T) {
	fake, srv := newDedupDojo(t)
	fake.status = http.StatusInternalServerError
	st := &memPushStore{snap: pushSnap("dmz")}
	p := newTestPusher(st, configured(srv.URL))

	assert.NoPanic(t, func() { p.OnRunDone(context.Background(), 7, "done") })
	p.Wait()

	pushes := st.history()
	assert.Len(t, 1, pushes)
	assert.False(t, pushes[0].OK)
	assert.Contain(t, "500", pushes[0].Error)
	assert.NotContain(t, testToken, pushes[0].Error)
	assert.Equal(t, 3, pushes[0].Findings)
	chip := must.Value(p.Status(context.Background()))
	assert.True(t, chip.Configured)
	assert.False(t, *chip.LastOK)

	// DefectDojo recovers: the next run reimports without duplicates.
	fake.mu.Lock()
	fake.status = 0
	fake.mu.Unlock()
	p.OnRunDone(context.Background(), 7, "done")
	p.Wait()
	pushes = st.history()
	assert.Len(t, 2, pushes)
	assert.True(t, pushes[1].OK)
	assert.Equal(t, 0, fake.duplicates)
	assert.True(t, *must.Value(p.Status(context.Background())).LastOK)
}

func TestPushFailureModes(t *testing.T) {
	_, srv := newDedupDojo(t)
	closed := httptest.NewServer(http.NotFoundHandler())
	closed.Close()
	cases := map[string]struct {
		s    Settings
		want string
	}{
		"unreachable": {configured(closed.URL), "reimport-scan/"},
		"401":         {func() Settings { s := configured(srv.URL); s.Token = "wrong-token-value"; return s }(), "401"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			st := &memPushStore{snap: pushSnap("dmz")}
			p := newTestPusher(st, tc.s)

			rec, err := p.PushRun(context.Background(), 7, "manual")

			assert.Error(t, err)
			assert.False(t, rec.OK)
			pushes := st.history()
			assert.Len(t, 1, pushes)
			assert.False(t, pushes[0].OK)
			assert.Contain(t, tc.want, pushes[0].Error)
			assert.NotContain(t, tc.s.Token, pushes[0].Error)
		})
	}
}

func TestPushErrorBeforeDojoRecorded(t *testing.T) {
	st := &memPushStore{snap: pushSnap("dmz"), runErr: errors.New("db down")}
	p := newTestPusher(st, configured("http://127.0.0.1:1"))

	_, err := p.PushRun(context.Background(), 7, "cli")

	assert.ErrorContain(t, "db down", err)
	pushes := st.history()
	assert.Len(t, 1, pushes)
	assert.False(t, pushes[0].OK)
	assert.Equal(t, "cli", pushes[0].Trigger)
	assert.Nil(t, pushes[0].RunID)
	assert.Contain(t, "db down", pushes[0].Error)
}

func TestPushSettingsErrorRecorded(t *testing.T) {
	st := &memPushStore{snap: pushSnap("dmz")}
	p := NewPusher(st, func(context.Context) (Settings, error) {
		return Settings{}, errors.New("open DefectDojo token (re-enter it in Settings): bad key")
	}, DefaultClient)

	_, err := p.PushRun(context.Background(), 7, "manual")

	assert.Error(t, err)
	pushes := st.history()
	assert.Len(t, 1, pushes)
	assert.Contain(t, "re-enter it", pushes[0].Error)
}

func TestPushRunRejectsUnknownTrigger(t *testing.T) {
	st := &memPushStore{snap: pushSnap("dmz")}
	p := newTestPusher(st, configured("http://127.0.0.1:1"))

	_, err := p.PushRun(context.Background(), 7, "cron")

	assert.ErrorContain(t, `unknown push trigger "cron"`, err)
	assert.Len(t, 0, st.history())
}

func TestReimportNoDuplicates(t *testing.T) {
	fake, srv := newDedupDojo(t)
	st := &memPushStore{snap: pushSnap("dmz")}
	p := newTestPusher(st, configured(srv.URL))

	first := must.Value(p.PushRun(context.Background(), 7, "manual"))
	second := must.Value(p.PushRun(context.Background(), 7, "manual"))

	assert.Equal(t, 0, fake.duplicates)
	assert.Equal(t, []string{"RampartEye – dmz", "RampartEye – dmz"}, fake.seenTitles())
	assert.Equal(t, 3, first.Added)
	assert.Equal(t, 3, second.Findings)
	assert.Equal(t, 0, second.Added)
	assert.Equal(t, 0, second.Closed)
	assert.Len(t, 1, fake.tests)
	assert.Len(t, 3, fake.tests["RampartEye – dmz"])

	// A service disappears: close_old_findings closes it, still no
	// duplicates.
	st.mu.Lock()
	st.snap.Services = st.snap.Services[1:]
	st.mu.Unlock()
	third := must.Value(p.PushRun(context.Background(), 7, "manual"))
	assert.Equal(t, 2, third.Findings)
	assert.Equal(t, 0, third.Added)
	assert.Equal(t, 1, third.Closed)
	assert.Equal(t, 0, fake.duplicates)
}

func TestPushTestTitlePerProfile(t *testing.T) {
	fake, srv := newDedupDojo(t)
	st := &memPushStore{snap: pushSnap("")}
	p := newTestPusher(st, configured(srv.URL))

	must.Value(p.PushRun(context.Background(), 0, "cli"))

	assert.Equal(t, []string{"RampartEye – ad-hoc"}, fake.seenTitles())
}

func TestAddedClosedFallbackWithoutStatistics(t *testing.T) {
	fake, srv := newDedupDojo(t)
	fake.noStats = true
	st := &memPushStore{snap: pushSnap("dmz")}
	p := newTestPusher(st, configured(srv.URL))

	first := must.Value(p.PushRun(context.Background(), 7, "manual"))
	st.mu.Lock()
	st.snap.Services = st.snap.Services[1:]
	st.mu.Unlock()
	second := must.Value(p.PushRun(context.Background(), 7, "manual"))

	assert.Equal(t, 3, first.Added) // first push of the profile: everything is new
	assert.Equal(t, 0, first.Closed)
	assert.Equal(t, 0, second.Added) // net change vs the previous push
	assert.Equal(t, 1, second.Closed)
}

func TestPushesSerializedPerProfile(t *testing.T) {
	fake, srv := newDedupDojo(t)
	fake.block = make(chan struct{})
	st := &memPushStore{snap: pushSnap("dmz")}
	p := newTestPusher(st, configured(srv.URL))

	var wg sync.WaitGroup
	for range 3 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = p.PushRun(context.Background(), 7, "manual")
		}()
	}
	time.Sleep(100 * time.Millisecond)
	close(fake.block)
	wg.Wait()

	assert.Equal(t, 1, fake.maxFlight)
	assert.Len(t, 3, st.history())
}

func TestOnRunDoneDoesNotBlock(t *testing.T) {
	fake, srv := newDedupDojo(t)
	fake.block = make(chan struct{})
	defer close(fake.block)
	st := &memPushStore{snap: pushSnap("dmz")}
	p := newTestPusher(st, configured(srv.URL))
	p.Timeout = 200 * time.Millisecond

	start := time.Now()
	p.OnRunDone(context.Background(), 7, "done")
	assert.Smaller(t, 50*time.Millisecond, time.Since(start))
	p.Wait()

	pushes := st.history()
	assert.Len(t, 1, pushes)
	assert.False(t, pushes[0].OK)
	assert.Contain(t, "deadline", pushes[0].Error)
}

func TestOnRunDoneOutlivesCallerContext(t *testing.T) {
	_, srv := newDedupDojo(t)
	st := &memPushStore{snap: pushSnap("dmz")}
	p := newTestPusher(st, configured(srv.URL))
	ctx, cancel := context.WithCancel(context.Background())

	p.OnRunDone(ctx, 7, "done")
	cancel()
	p.Wait()

	pushes := st.history()
	assert.Len(t, 1, pushes)
	assert.True(t, pushes[0].OK)
}

func TestOnRunDoneRecoversPanic(t *testing.T) {
	st := &memPushStore{snap: pushSnap("dmz"), panics: true}
	p := newTestPusher(st, configured("http://127.0.0.1:1"))

	assert.NoPanic(t, func() {
		p.OnRunDone(context.Background(), 7, "done")
		p.Wait()
	})
}

func TestChipLastFailed(t *testing.T) {
	st := &memPushStore{}
	s := Settings{URL: "https://dojo.example", TokenSet: true}
	ctx := context.Background()

	chip := must.Value(Status(ctx, st, s))
	assert.True(t, chip.Configured)
	assert.Nil(t, chip.LastOK) // never pushed
	assert.Zero(t, chip.LastAt)

	must.Nil(st.RecordDojoPush(ctx, store.DojoPush{Trigger: "auto", Findings: 36, OK: true}))
	must.Nil(st.RecordDojoPush(ctx, store.DojoPush{Trigger: "auto", Findings: 40, OK: false,
		Error: "defectdojo reimport-scan/: HTTP 500"}))

	chip = must.Value(Status(ctx, st, s))
	assert.True(t, chip.Configured)
	assert.False(t, *chip.LastOK)
	assert.Equal(t, st.history()[1].At, chip.LastAt)
	assert.Equal(t, 36, chip.Findings) // from the last successful push

	assert.False(t, must.Value(Status(ctx, st, Settings{URL: "https://dojo.example"})).Configured)
}

func TestPushRecordErrorNeverHasToken(t *testing.T) {
	// The settings error text is produced outside the client; the pusher
	// still masks the token in whatever it records.
	st := &memPushStore{snap: pushSnap("dmz"), runErr: errors.New("failed with " + testToken)}
	p := newTestPusher(st, configured("http://127.0.0.1:1"))

	_, err := p.PushRun(context.Background(), 7, "manual")

	assert.NotContain(t, testToken, err.Error())
	assert.NotContain(t, testToken, st.history()[0].Error)
	assert.Contain(t, "[redacted]", st.history()[0].Error)
}

func TestStoredSettingsOpensToken(t *testing.T) {
	ctx, st, box := context.Background(), &memStore{}, testBox(t)
	src := StoredSettings(st, box, config.Config{})

	s := must.Value(src(ctx)) // nothing stored: not configured, no error
	assert.False(t, s.configured())

	must.Nil(SaveSettings(ctx, st, box, config.Config{}, Settings{URL: "https://d.example", Token: "tok", AutoPush: true}))
	s = must.Value(src(ctx))
	assert.Equal(t, "tok", s.Token)
	assert.True(t, s.configured())

	_, err := StoredSettings(st, testBoxOther(t), config.Config{})(ctx)
	assert.ErrorContain(t, "re-enter it in Settings", err)

	env := must.Value(StoredSettings(&memStore{}, nil, envCfg())(ctx))
	assert.Equal(t, "env-token", env.Token)
}

func testBoxOther(t *testing.T) *secret.Box {
	t.Helper()
	return must.Value(secret.NewBox(bytes.Repeat([]byte{7}, 32)))
}
