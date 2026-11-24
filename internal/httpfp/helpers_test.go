package httpfp

import (
	"context"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"testing"

	"github.com/ctx42/testing/pkg/assert"

	"github.com/chrobson/ramparteye/internal/model"
	"github.com/chrobson/ramparteye/internal/scope"
)

// loopbackScope allows 127.0.0.0/8 only.
func loopbackScope(t *testing.T) scope.Scope {
	t.Helper()
	s, err := scope.New([]netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// newProber returns a prober scoped to loopback with favicon fetching off.
func newProber(t *testing.T, mod func(*Options)) *HTTPProber {
	t.Helper()
	o := Options{Scope: loopbackScope(t), SkipFavicon: true}
	if mod != nil {
		mod(&o)
	}
	return New(o)
}

// endpointFor converts an httptest server URL into a model.Endpoint.
func endpointFor(t *testing.T, rawURL, vhost string) model.Endpoint {
	t.Helper()
	scheme, hostport, _ := strings.Cut(rawURL, "://")
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		t.Fatal(err)
	}
	p, _ := strconv.Atoi(port)
	return model.Endpoint{
		ServiceID: 7,
		Scheme:    scheme,
		Key: model.AssetKey{
			IP: netip.MustParseAddr(host), Port: uint16(p),
			Proto: "tcp", VHost: vhost,
		},
	}
}

// probe runs Probe and fails the test on error.
func probe(t *testing.T, p *HTTPProber, ep model.Endpoint) model.HTTPObs {
	t.Helper()
	obs, err := p.Probe(context.Background(), ep)
	if !assert.NoError(t, err) {
		t.FailNow()
	}
	return obs
}
