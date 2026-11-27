//go:build integration

package main

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/ctx42/testing/pkg/assert"

	"github.com/chrobson/ramparteye/internal/config"
	"github.com/chrobson/ramparteye/internal/notify"
	"github.com/chrobson/ramparteye/internal/store"
)

// A run that finishes reaches the webhook through runner.OnRunDone, next
// to the DefectDojo pusher, and is recorded in the delivery history.
func TestFinishedRunReachesNotifierIntegration(t *testing.T) {
	ctx := context.Background()
	pool, _ := migrated(t)
	st := store.New(pool)
	var mu sync.Mutex
	var bodies [][]byte
	var sigs []string
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies, sigs = append(bodies, b), append(sigs, r.Header.Get(notify.HeaderSignature))
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer hook.Close()
	cfg, err := config.Load(func(k string) string {
		return map[string]string{"RAMPART_SECRETS_DIR": t.TempDir()}[k]
	})
	assert.NoError(t, err)
	box, _, err := loadBox(&cfg, true)
	assert.NoError(t, err)
	// The first run is the baseline without changes: notify it anyway.
	assert.NoError(t, notify.SaveSettings(ctx, st, box, notify.Settings{Enabled: true, URL: hook.URL + "/hook/x",
		Format: notify.FormatJSON, Secret: "sig", BaseURL: "https://rampart.example"}))
	log := slog.New(slog.DiscardHandler)
	sc := mustScope(t, "127.0.0.1/32")
	res, err := ensureProfile(ctx, st, sc, nil, "Notify", []string{"127.0.0.1"}, nil, 100)
	assert.NoError(t, err)
	s := newScanner(cfg, st, sc, box, log, fakeNmap{})
	assert.NoError(t, s.runner.Recover(ctx))

	runID, err := s.runner.Start(ctx, res.ConfigID)
	assert.NoError(t, err)
	s.runner.Wait()
	shutdown(log, 5*time.Second, shutdownSteps{waitRuns: s.runner.Wait, waitNotify: s.notifier.Wait,
		pushBudget: 5 * time.Second, closePusher: s.pusher.Close, closeNotifier: s.notifier.Close})

	ds, err := st.NotifyDeliveries(ctx, 10)
	assert.NoError(t, err)
	assert.Len(t, 1, ds)
	assert.True(t, ds[0].OK, ds[0].Error)
	assert.Equal(t, runID, *ds[0].RunID)
	assert.Equal(t, hook.URL, ds[0].Endpoint)
	mu.Lock()
	defer mu.Unlock()
	assert.Len(t, 1, bodies)
	assert.Equal(t, notify.Sign("sig", bodies[0]), sigs[0])
	var m map[string]any
	assert.NoError(t, json.Unmarshal(bodies[0], &m))
	assert.Equal(t, "scan.finished", m["event"])
	assert.Equal(t, "Notify", m["run"].(map[string]any)["profile"])
	assert.NotEqual(t, "", m["instance"])
	assert.Equal(t, "https://rampart.example/scans/"+strconv.FormatInt(runID, 10), m["links"].(map[string]any)["run"])
}
