package httpfp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ctx42/testing/pkg/assert"

	"github.com/chrobson/ramparteye/internal/safety"
)

// Every request the prober sends is counted in the safety meter of its
// context, including the favicon and the latency sample.
func Test_HTTPProber_counts_requests_in_meter(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<title>x</title>"))
	}))
	defer srv.Close()
	p := newProber(t, func(o *Options) { o.SkipFavicon = false; o.LatencySample = true })
	m := safety.NewMeter()
	ctx := safety.WithMeter(context.Background(), m)

	_, err := p.Probe(ctx, endpointFor(t, srv.URL, ""))
	assert.NoError(t, err)
	_, err = p.FetchPath(ctx, endpointFor(t, srv.URL, ""), http.MethodHead, "/x", nil)
	assert.NoError(t, err)

	got := m.Snapshot().Methods
	assert.Equal(t, 2, got[http.MethodGet])  // page and /favicon.ico
	assert.Equal(t, 2, got[http.MethodHead]) // latency sample and the path probe
}
