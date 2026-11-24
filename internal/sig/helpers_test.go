package sig

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"strconv"
	"sync"
	"testing"

	"github.com/ctx42/testing/pkg/must"

	"github.com/chrobson/ramparteye/internal/model"
	"github.com/chrobson/ramparteye/internal/scope"
)

// fakeFetcher serves path probes from a map and records every request.
type fakeFetcher struct {
	mu    sync.Mutex
	resp  map[string]ProbeResponse // "GET /path"
	calls []string
}

func (f *fakeFetcher) Fetch(_ context.Context, _ model.ServiceObs, _ model.HTTPObs, req ProbeRequest) (ProbeResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if req.Method != "GET" && req.Method != "HEAD" {
		return ProbeResponse{}, fmt.Errorf("method %s", req.Method)
	}
	key := req.Method + " " + req.Path
	f.calls = append(f.calls, key)
	if r, ok := f.resp[key]; ok {
		return r, nil
	}
	return ProbeResponse{Status: 404, Header: http.Header{}, Body: []byte("not found")}, nil
}

func (f *fakeFetcher) Calls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

func svc(port uint16, vhost string) model.ServiceObs {
	return model.ServiceObs{ID: int64(port), Key: model.AssetKey{IP: netip.MustParseAddr("10.20.1.5"), Port: port, Proto: "tcp", VHost: vhost}}
}

func httpObs(port uint16, title, body string, hdr map[string][]string) model.HTTPObs {
	if hdr == nil {
		hdr = map[string][]string{}
	}
	return model.HTTPObs{ServiceID: int64(port), URL: "http://10.20.1.5:" + strconv.Itoa(int(port)) + "/", Status: 200, Title: title, Body: []byte(body), Headers: hdr}
}

func mustParse(t *testing.T, doc string) *Signature {
	t.Helper()
	s, err := Parse([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func match(e *Engine, s model.ServiceObs, o model.HTTPObs) []model.Detection {
	return e.Match(context.Background(), s, o)
}

// loopbackScope allows 127.0.0.0/8 only.
func loopbackScope(t *testing.T) scope.Scope {
	t.Helper()
	return must.Value(scope.New([]netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}, nil, nil))
}
