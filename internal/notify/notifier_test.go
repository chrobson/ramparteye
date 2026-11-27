package notify

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ctx42/testing/pkg/assert"
	"github.com/ctx42/testing/pkg/must"

	"github.com/chrobson/ramparteye/internal/store"
)

// received is one request the webhook receiver got.
type received struct {
	method string
	path   string
	header http.Header
	body   []byte
}

// receiver is an httptest webhook endpoint; respond answers request n
// (0-based).
type receiver struct {
	srv     *httptest.Server
	mu      sync.Mutex
	got     []received
	respond func(w http.ResponseWriter, r *http.Request, n int)
}

func newReceiver(t *testing.T, respond func(w http.ResponseWriter, r *http.Request, n int)) *receiver {
	t.Helper()
	rc := &receiver{respond: respond}
	rc.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		rc.mu.Lock()
		n := len(rc.got)
		rc.got = append(rc.got, received{method: r.Method, path: r.URL.RequestURI(), header: r.Header.Clone(), body: body})
		rc.mu.Unlock()
		if rc.respond != nil {
			rc.respond(w, r, n)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(rc.srv.Close)
	return rc
}

func (rc *receiver) requests() []received {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	return append([]received(nil), rc.got...)
}

// url is the receiver's webhook URL; its path is the credential.
func (rc *receiver) url() string { return rc.srv.URL + "/hooks/SECRETPATH" }

type fixture struct {
	st   *memStore
	n    *Notifier
	logs *bytes.Buffer
	ctx  context.Context
}

func newFixture(t *testing.T, s Settings) *fixture {
	t.Helper()
	f := &fixture{st: newMemStore(), logs: &bytes.Buffer{}, ctx: context.Background()}
	box := testBox(t)
	if s.URL != "" || s.Enabled {
		must.Nil(SaveSettings(f.ctx, f.st, box, s))
	}
	f.n = New(f.st, box, Options{Instance: instID, UserAgent: "ramparteye/test", Backoff: []time.Duration{0, 0},
		Log: slog.New(slog.NewTextHandler(&lockedWriter{w: f.logs}, nil)), Now: func() time.Time { return sentAt }})
	t.Cleanup(func() { _ = f.n.Close(context.Background()) })
	return f
}

// lockedWriter serialises writes of concurrent deliveries.
type lockedWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

func jsonSettings(url string) Settings {
	return Settings{Enabled: true, URL: url, Format: FormatJSON, Secret: hookSecret, OnlyChanges: true,
		BaseURL: baseURL}
}

// done runs the hook for run d with status and waits for the delivery.
func (f *fixture) done(d *runData, status string) {
	d.Run.Status = status
	f.st.addRun(d)
	f.n.OnRunDone(f.ctx, d.Run.ID, status)
	f.n.Wait()
}

func TestRunDoneDeliversSignedJSON(t *testing.T) {
	rc := newReceiver(t, nil)
	f := newFixture(t, jsonSettings(rc.url()))

	f.done(sampleRun(), store.RunDone)

	reqs := rc.requests()
	assert.Len(t, 1, reqs)
	r := reqs[0]
	assert.Equal(t, http.MethodPost, r.method)
	assert.Equal(t, "/hooks/SECRETPATH", r.path)
	assert.Equal(t, "application/json", r.header.Get("Content-Type"))
	assert.Equal(t, "ramparteye/test", r.header.Get("User-Agent"))
	assert.Equal(t, "scan.finished", r.header.Get("X-Rampart-Event"))
	assert.Len(t, 32, r.header.Get("X-Rampart-Delivery"))
	assert.Equal(t, strconv.FormatInt(sentAt.Unix(), 10), r.header.Get("X-Rampart-Timestamp"))
	mac := hmac.New(sha256.New, []byte(hookSecret))
	mac.Write(r.body)
	assert.Equal(t, "sha256="+hex.EncodeToString(mac.Sum(nil)), r.header.Get("X-Rampart-Signature"))
	got := decode(t, r.body)
	assert.Equal(t, "scan.finished", got["event"])
	assert.Equal(t, 42.0, got["run"].(map[string]any)["id"])
	assert.Equal(t, "https://rampart.example/scans/42", got["links"].(map[string]any)["run"])

	h := f.st.history()
	assert.Len(t, 1, h)
	assert.Equal(t, int64(42), *h[0].RunID)
	assert.Equal(t, "auto", h[0].Trigger)
	assert.Equal(t, "scan.finished", h[0].Event)
	assert.Equal(t, rc.srv.URL, h[0].Endpoint)
	assert.Equal(t, 1, h[0].Attempts)
	assert.Equal(t, 204, *h[0].Status)
	assert.True(t, h[0].OK)
	assert.Equal(t, "", h[0].Error)
}

func TestRunDoneWithoutSecretIsUnsigned(t *testing.T) {
	rc := newReceiver(t, nil)
	s := jsonSettings(rc.url())
	s.Secret = ""
	f := newFixture(t, s)

	f.done(sampleRun(), store.RunDone)

	r := rc.requests()[0]
	assert.Equal(t, "", r.header.Get("X-Rampart-Signature"))
	assert.NotEqual(t, "", r.header.Get("X-Rampart-Timestamp"))
}

func TestSlackFormat(t *testing.T) {
	rc := newReceiver(t, func(w http.ResponseWriter, _ *http.Request, _ int) { _, _ = io.WriteString(w, "ok") })
	s := jsonSettings(rc.url())
	s.Format = FormatSlack
	f := newFixture(t, s)

	f.done(sampleRun(), store.RunDone)

	var p map[string]string
	must.Nil(json.Unmarshal(rc.requests()[0].body, &p))
	assert.Len(t, 1, p)
	assert.Contain(t, "*RampartEye*: scan #42 `Campus` finished", p["text"])
	assert.Equal(t, 200, *f.st.history()[0].Status)
}

func TestWhichRunsAreNotified(t *testing.T) {
	quiet := func() *runData {
		d := sampleRun()
		d.Changes = nil
		return d
	}
	for name, tc := range map[string]struct {
		settings func(Settings) Settings
		run      func() *runData
		status   string
		event    string // "" = nothing sent
	}{
		"done with changes":           {nil, sampleRun, store.RunDone, EventFinished},
		"done without changes":        {nil, quiet, store.RunDone, ""},
		"done without changes, all":   {func(s Settings) Settings { s.OnlyChanges = false; return s }, quiet, store.RunDone, EventFinished},
		"failed, not wanted":          {nil, sampleRun, store.RunFailed, ""},
		"failed, wanted":              {func(s Settings) Settings { s.NotifyFailed = true; return s }, quiet, store.RunFailed, EventFailed},
		"cancelled":                   {func(s Settings) Settings { s.NotifyFailed, s.OnlyChanges = true, false; return s }, sampleRun, store.RunCancelled, ""},
		"paused":                      {nil, sampleRun, store.RunPaused, ""},
		"disabled":                    {func(s Settings) Settings { s.Enabled = false; return s }, sampleRun, store.RunDone, ""},
		"no url (cleared)":            {func(s Settings) Settings { s.Enabled, s.URL = false, ""; return s }, sampleRun, store.RunDone, ""},
		"failed run with only change": {func(s Settings) Settings { s.NotifyFailed = true; return s }, sampleRun, store.RunFailed, EventFailed},
	} {
		t.Run(name, func(t *testing.T) {
			rc := newReceiver(t, nil)
			s := jsonSettings(rc.url())
			if tc.settings != nil {
				s = tc.settings(s)
			}
			f := newFixture(t, s)

			f.done(tc.run(), tc.status)

			reqs := rc.requests()
			if tc.event == "" {
				assert.Len(t, 0, reqs)
				assert.Len(t, 0, f.st.history())
				return
			}
			assert.Len(t, 1, reqs)
			assert.Equal(t, tc.event, decode(t, reqs[0].body)["event"])
			assert.Equal(t, tc.event, f.st.history()[0].Event)
		})
	}
}

func TestRetriesOnServerErrorsAnd429(t *testing.T) {
	codes := []int{503, 429, 200}
	rc := newReceiver(t, func(w http.ResponseWriter, _ *http.Request, n int) { w.WriteHeader(codes[n]) })
	f := newFixture(t, jsonSettings(rc.url()))

	f.done(sampleRun(), store.RunDone)

	reqs := rc.requests()
	assert.Len(t, 3, reqs)
	assert.Equal(t, reqs[0].header.Get("X-Rampart-Delivery"), reqs[2].header.Get("X-Rampart-Delivery"))
	assert.Equal(t, reqs[0].body, reqs[2].body)
	h := f.st.history()[0]
	assert.True(t, h.OK)
	assert.Equal(t, 3, h.Attempts)
	assert.Equal(t, 200, *h.Status)
}

func TestGivesUpAfterThreeAttempts(t *testing.T) {
	rc := newReceiver(t, func(w http.ResponseWriter, _ *http.Request, _ int) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = io.WriteString(w, "upstream says "+hookSecret)
	})
	f := newFixture(t, jsonSettings(rc.url()))

	f.done(sampleRun(), store.RunDone)

	assert.Len(t, 3, rc.requests())
	h := f.st.history()[0]
	assert.False(t, h.OK)
	assert.Equal(t, 3, h.Attempts)
	assert.Equal(t, 502, *h.Status)
	assert.Equal(t, rc.srv.URL+": HTTP 502 Bad Gateway", h.Error) // the body is never recorded
}

func TestNoRetryOnClientError(t *testing.T) {
	rc := newReceiver(t, func(w http.ResponseWriter, _ *http.Request, _ int) { w.WriteHeader(http.StatusNotFound) })
	f := newFixture(t, jsonSettings(rc.url()))

	f.done(sampleRun(), store.RunDone)

	assert.Len(t, 1, rc.requests())
	h := f.st.history()[0]
	assert.False(t, h.OK)
	assert.Equal(t, 1, h.Attempts)
	assert.Equal(t, rc.srv.URL+": HTTP 404 Not Found", h.Error)
}

func TestRedirectsAreNotFollowed(t *testing.T) {
	other := newReceiver(t, nil)
	rc := newReceiver(t, func(w http.ResponseWriter, r *http.Request, _ int) {
		http.Redirect(w, r, other.url(), http.StatusTemporaryRedirect)
	})
	f := newFixture(t, jsonSettings(rc.url()))

	f.done(sampleRun(), store.RunDone)

	assert.Len(t, 1, rc.requests())
	assert.Len(t, 0, other.requests())
	h := f.st.history()[0]
	assert.False(t, h.OK)
	assert.Equal(t, 307, *h.Status)
	assert.Contain(t, "redirects are not followed", h.Error)
}

func TestNetworkErrorIsRetriedAndSanitised(t *testing.T) {
	ln := must.Value(net.Listen("tcp", "127.0.0.1:0"))
	addr := ln.Addr().String()
	must.Nil(ln.Close()) // nothing listens: connection refused
	f := newFixture(t, jsonSettings("http://"+addr+"/hooks/SECRETPATH?token=SECRETQUERY"))

	f.done(sampleRun(), store.RunDone)

	h := f.st.history()[0]
	assert.False(t, h.OK)
	assert.Nil(t, h.Status)
	assert.Equal(t, 3, h.Attempts)
	assert.True(t, strings.HasPrefix(h.Error, "http://"+addr+": "), h.Error)
	assert.Contain(t, "refused", h.Error)
	for _, out := range []string{h.Error, f.logs.String()} {
		assert.NotContain(t, "SECRET", out)
		assert.NotContain(t, "hooks/", out)
	}
}

func TestResponseBodyIsCapped(t *testing.T) {
	rc := newReceiver(t, func(w http.ResponseWriter, _ *http.Request, _ int) {
		chunk := bytes.Repeat([]byte("x"), 64<<10)
		for range 256 { // 16 MiB unless the client stops reading
			if _, err := w.Write(chunk); err != nil {
				return
			}
		}
	})
	f := newFixture(t, jsonSettings(rc.url()))

	f.done(sampleRun(), store.RunDone)

	assert.True(t, f.st.history()[0].OK)
}

func TestTimeoutPerAttempt(t *testing.T) {
	release := make(chan struct{})
	rc := newReceiver(t, func(w http.ResponseWriter, r *http.Request, _ int) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	})
	defer close(release)
	f := newFixture(t, jsonSettings(rc.url()))
	f.n.opt.AttemptTimeout = 50 * time.Millisecond

	f.done(sampleRun(), store.RunDone)

	h := f.st.history()[0]
	assert.Len(t, 3, rc.requests())
	assert.Equal(t, rc.srv.URL+": timed out", h.Error)
}

func TestCloseCancelsDeliveriesInFlight(t *testing.T) {
	entered := make(chan struct{}, 3)
	rc := newReceiver(t, func(w http.ResponseWriter, r *http.Request, _ int) {
		entered <- struct{}{}
		<-r.Context().Done()
	})
	f := newFixture(t, jsonSettings(rc.url()))
	d := sampleRun()
	f.st.addRun(d)
	f.n.OnRunDone(f.ctx, d.Run.ID, store.RunDone)
	<-entered

	assert.NoError(t, f.n.Close(context.Background()))

	h := f.st.history()
	assert.Len(t, 1, h)
	assert.False(t, h[0].OK)
	assert.Equal(t, rc.srv.URL+": cancelled", h[0].Error)
	assert.Len(t, 1, rc.requests()) // no retry after Close

	// Later runs are dropped.
	f.n.OnRunDone(f.ctx, d.Run.ID, store.RunDone)
	f.n.Wait()
	assert.Len(t, 1, f.st.history())
	_, err := f.n.SendTest(f.ctx)
	assert.ErrorIs(t, ErrClosed, err)
}

func TestCloseWaitIsBounded(t *testing.T) {
	f := newFixture(t, Settings{})
	done := must.Value(f.n.begin())
	defer done()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	assert.ErrorIs(t, context.DeadlineExceeded, f.n.Close(ctx))
}

func TestOnRunDoneDoesNotBlock(t *testing.T) {
	release := make(chan struct{})
	rc := newReceiver(t, func(w http.ResponseWriter, r *http.Request, _ int) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	})
	f := newFixture(t, jsonSettings(rc.url()))
	d := sampleRun()
	f.st.addRun(d)
	t0 := time.Now()

	f.n.OnRunDone(f.ctx, d.Run.ID, store.RunDone)

	assert.True(t, time.Since(t0) < 100*time.Millisecond)
	close(release)
	f.n.Wait()
	assert.True(t, f.st.history()[0].OK)
}

func TestUnopenableURLIsRecorded(t *testing.T) {
	rc := newReceiver(t, nil)
	f := newFixture(t, jsonSettings(rc.url()))
	f.n.box = testBoxOther(t)

	f.done(sampleRun(), store.RunDone)

	assert.Len(t, 0, rc.requests())
	h := f.st.history()[0]
	assert.False(t, h.OK)
	assert.Contain(t, "re-enter it in Settings", h.Error)
	assert.Equal(t, rc.srv.URL, h.Endpoint)
}

func TestRunThatCannotBeLoadedIsRecorded(t *testing.T) {
	rc := newReceiver(t, nil)
	f := newFixture(t, jsonSettings(rc.url()))

	f.n.OnRunDone(f.ctx, 999, store.RunDone)
	f.n.Wait()

	assert.Len(t, 0, rc.requests())
	h := f.st.history()[0]
	assert.False(t, h.OK)
	assert.Contain(t, "load run", h.Error)
}

func TestPanicIsRecordedWithFixedMessage(t *testing.T) {
	rc := newReceiver(t, nil)
	f := newFixture(t, jsonSettings(rc.url()))
	f.st.addRun(sampleRun())
	f.st.panics = true

	f.n.OnRunDone(f.ctx, 42, store.RunDone)
	f.n.Wait()

	h := f.st.history()
	assert.Len(t, 1, h)
	assert.Equal(t, panicMessage, h[0].Error)
	assert.Contain(t, "panicked", f.logs.String())
}

func TestSettingsUnavailableIsLoggedOnly(t *testing.T) {
	f := newFixture(t, Settings{})
	f.st.cfgErr = store.ErrNotFound
	f.st.cfg = nil

	f.done(sampleRun(), store.RunDone)

	assert.Len(t, 0, f.st.history())
}

func TestSendTest(t *testing.T) {
	rc := newReceiver(t, nil)
	s := jsonSettings(rc.url())
	s.Enabled = false // a test works before notifications are switched on
	f := newFixture(t, s)

	d, err := f.n.SendTest(f.ctx)

	assert.NoError(t, err)
	assert.True(t, d.OK)
	assert.Equal(t, 204, d.Status)
	req := rc.requests()[0]
	assert.Equal(t, "test", req.header.Get("X-Rampart-Event"))
	got := decode(t, req.body)
	assert.Equal(t, "test", got["event"])
	assert.Nil(t, got["run"])
	h := f.st.history()[0]
	assert.Equal(t, "test", h.Trigger)
	assert.Equal(t, "test", h.Event)
	assert.Nil(t, h.RunID)

	// With a finished run the test carries its summary, not its run id in
	// the history.
	f.st.addRun(sampleRun())
	_, err = f.n.SendTest(f.ctx)
	assert.NoError(t, err)
	assert.Equal(t, 42.0, decode(t, rc.requests()[1].body)["run"].(map[string]any)["id"])
	assert.Nil(t, f.st.history()[1].RunID)
}

func TestSendTestFailure(t *testing.T) {
	rc := newReceiver(t, func(w http.ResponseWriter, _ *http.Request, _ int) { w.WriteHeader(http.StatusForbidden) })
	f := newFixture(t, jsonSettings(rc.url()))

	d, err := f.n.SendTest(f.ctx)

	assert.Error(t, err)
	assert.False(t, d.OK)
	assert.Equal(t, 403, d.Status)
	assert.Equal(t, rc.srv.URL+": HTTP 403 Forbidden", d.Error)
	assert.Equal(t, d.Error, err.Error())
	assert.Len(t, 1, f.st.history())
}

func TestSendTestNotConfigured(t *testing.T) {
	f := newFixture(t, Settings{})

	_, err := f.n.SendTest(f.ctx)

	assert.ErrorIs(t, ErrNotConfigured, err)
	assert.Len(t, 0, f.st.history())
}

func TestDeliveriesNewestFirst(t *testing.T) {
	rc := newReceiver(t, nil)
	f := newFixture(t, jsonSettings(rc.url()))
	must.Value(f.n.SendTest(f.ctx))
	f.done(sampleRun(), store.RunDone)

	ds := must.Value(f.n.Deliveries(f.ctx, 10))

	assert.Len(t, 2, ds)
	assert.Equal(t, "auto", ds[0].Trigger)
	assert.Len(t, 1, must.Value(f.n.Deliveries(f.ctx, 1)))
}

func TestCustomHTTPClientNeverFollowsRedirects(t *testing.T) {
	other := newReceiver(t, nil)
	rc := newReceiver(t, func(w http.ResponseWriter, r *http.Request, _ int) {
		http.Redirect(w, r, other.url(), http.StatusFound)
	})
	f := newFixture(t, jsonSettings(rc.url()))
	n := New(f.st, testBox(t), Options{HTTPClient: &http.Client{}, Backoff: []time.Duration{0, 0},
		Log: slog.New(slog.DiscardHandler)})
	defer func() { _ = n.Close(context.Background()) }()

	d, err := n.SendTest(f.ctx)

	assert.Error(t, err)
	assert.Equal(t, 302, d.Status)
	assert.Len(t, 0, other.requests())
	assert.Contain(t, "ramparteye", rc.requests()[0].header.Get("User-Agent")) // default agent
}
