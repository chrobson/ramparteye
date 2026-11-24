package httpfp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/ctx42/testing/pkg/assert"

	"github.com/chrobson/ramparteye/internal/model"
	"github.com/chrobson/ramparteye/internal/scope"
)

// fakeResolver maps host names to fixed addresses.
func fakeResolver(m map[string][]string) Resolver {
	return func(_ context.Context, host string) ([]netip.Addr, error) {
		var out []netip.Addr
		for _, s := range m[host] {
			out = append(out, netip.MustParseAddr(s))
		}
		if out == nil {
			return nil, fmt.Errorf("no such host %s", host)
		}
		return out, nil
	}
}

func Test_HTTPProber_only_GET_and_HEAD(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
	}))
	defer srv.Close()
	p := newProber(t, nil)
	tgt := endpointTarget("127.0.0.1", "")

	for _, m := range []string{"POST", "PUT", "DELETE", "PATCH", "OPTIONS"} {
		t.Run(m, func(t *testing.T) {
			// guard in fetch
			_, err := p.fetch(context.Background(), p.client(tgt, nil), m, srv.URL, 10)
			assert.ErrorIs(t, ErrMethodNotAllowed, err)

			// guard in the transport itself
			req, _ := http.NewRequest(m, srv.URL, nil)
			_, err = p.client(tgt, nil).Do(req)
			assert.ErrorIs(t, ErrMethodNotAllowed, err)
		})
	}
	for _, m := range []string{"GET", "HEAD"} {
		_, err := p.fetch(context.Background(), p.client(tgt, nil), m, srv.URL, 10)
		assert.NoError(t, err)
	}
	assert.Equal(t, int32(2), hits.Load())
}

func Test_HTTPProber_Probe_endpoint_out_of_scope(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
	}))
	defer srv.Close()
	other, err := scope.New([]netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}, nil, nil)
	assert.NoError(t, err)

	t.Run("outside allowed networks", func(t *testing.T) {
		p := New(Options{Scope: other})

		_, err := p.Probe(context.Background(), endpointFor(t, srv.URL, ""))

		assert.ErrorIs(t, ErrNotAllowed, err)
	})

	t.Run("empty scope refuses everything", func(t *testing.T) {
		p := New(Options{})

		_, err := p.Probe(context.Background(), endpointFor(t, srv.URL, ""))

		assert.ErrorIs(t, ErrNotAllowed, err)
	})

	t.Run("excluded address", func(t *testing.T) {
		s, err := scope.New(
			[]netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}, nil,
			[]netip.Addr{netip.MustParseAddr("127.0.0.1")},
		)
		assert.NoError(t, err)

		_, err = New(Options{Scope: s}).Probe(context.Background(), endpointFor(t, srv.URL, ""))

		assert.ErrorIs(t, ErrNotAllowed, err)
	})

	assert.Equal(t, int32(0), hits.Load())
}

func Test_HTTPProber_redirect_out_of_scope_stopped(t *testing.T) {
	resolver := fakeResolver(map[string][]string{
		"out.test":    {"10.9.9.9"},
		"in.test":     {"127.0.0.1"},
		"rebind.test": {"127.0.0.1", "10.9.9.9"},
		"mapped.test": {"::ffff:10.9.9.9"},
		"nat64.test":  {"64:ff9b::7f00:1"},
	})
	tests := []struct {
		name     string
		target   string
		followed bool
	}{
		{"literal out of scope ip", "http://10.9.9.9:%d/", false},
		{"domain resolving out of scope", "http://out.test:%d/", false},
		{"dns rebinding mixed answer", "http://rebind.test:%d/", false},
		{"ipv4-mapped out of scope", "http://mapped.test:%d/", false},
		{"nat64 address", "http://nat64.test:%d/", false},
		{"unresolvable host", "http://nx.test:%d/", false},
		{"domain resolving in scope", "http://in.test:%d/", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var port int
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.HasPrefix(r.Host, "in.test") {
					fmt.Fprint(w, "<title>followed</title>")
					return
				}
				http.Redirect(w, r, fmt.Sprintf(tc.target, port), http.StatusFound)
			}))
			defer srv.Close()
			ep := endpointFor(t, srv.URL, "")
			port = int(ep.Key.Port) // same port: only the scope check decides
			var dialled []string
			var mu sync.Mutex
			d := &net.Dialer{}
			p := newProber(t, func(o *Options) {
				o.Resolver = resolver
				o.Retries = -1
				o.DialContext = func(ctx context.Context, n, a string) (net.Conn, error) {
					mu.Lock()
					dialled = append(dialled, a)
					mu.Unlock()
					return d.DialContext(ctx, n, a)
				}
			})

			obs := probe(t, p, ep)

			mu.Lock()
			defer mu.Unlock()
			for _, a := range dialled {
				assert.True(t, strings.HasPrefix(a, "127.0.0.1:"), a)
			}
			if tc.followed {
				assert.Equal(t, 200, obs.Status)
				assert.Equal(t, "followed", obs.Title)
				assert.Len(t, 1, obs.Redirects)
				assert.Len(t, 2, dialled)
				return
			}
			assert.Equal(t, 302, obs.Status)
			assert.Len(t, 2, obs.Redirects)
			assert.Equal(t, 0, obs.Redirects[1].Status)
			assert.Len(t, 1, dialled)
		})
	}
}

func Test_HTTPProber_redirect_scheme_and_empty_location(t *testing.T) {
	for _, loc := range []string{"", "ftp://127.0.0.1/", "javascript:alert(1)"} {
		t.Run(loc, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if loc != "" {
					w.Header().Set("Location", loc)
				}
				w.WriteHeader(http.StatusFound)
			}))
			defer srv.Close()

			obs := probe(t, newProber(t, nil), endpointFor(t, srv.URL, ""))

			assert.Equal(t, 302, obs.Status)
		})
	}
}

func Test_dial_pins_and_checks_resolved_address(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<title>ok</title>")
	}))
	defer srv.Close()

	t.Run("vhost is dialled at the endpoint ip, not resolved", func(t *testing.T) {
		var resolved atomic.Int32
		p := newProber(t, func(o *Options) {
			o.Resolver = func(context.Context, string) ([]netip.Addr, error) {
				resolved.Add(1)
				return []netip.Addr{netip.MustParseAddr("10.9.9.9")}, nil
			}
		})

		obs := probe(t, p, endpointFor(t, srv.URL, "app.test"))

		assert.Equal(t, "ok", obs.Title)
		assert.Equal(t, int32(0), resolved.Load())
	})
}

func Test_HTTPProber_hostile_content_bounded(t *testing.T) {
	t.Run("headers and cookies", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			for i := 0; i < 150; i++ {
				w.Header().Set("X-H"+strconv.Itoa(1000+i), "v")
			}
			w.Header().Set("X-Long", strings.Repeat("a", 10_000))
			w.Header().Set("X-Bad", "ok\xff\xfe")
			for i := 0; i < 150; i++ {
				w.Header().Add("Set-Cookie", "c"+strconv.Itoa(i)+"=v")
			}
			http.SetCookie(w, &http.Cookie{Name: strings.Repeat("n", 1000), Value: "v"})
		}))
		defer srv.Close()

		obs := probe(t, newProber(t, nil), endpointFor(t, srv.URL, ""))

		assert.True(t, len(obs.Headers) <= maxHeaders)
		for k, vs := range obs.Headers {
			assert.True(t, len(k) <= maxHeaderName)
			for _, v := range vs {
				assert.True(t, len(v) <= maxHeaderValue)
				assert.True(t, validUTF8(v))
			}
		}
		assert.True(t, len(obs.Cookies) <= maxCookies)
		for _, c := range obs.Cookies {
			assert.True(t, len(c.Name) <= maxHeaderName)
		}
	})

	t.Run("redirect url bounded", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/"+strings.Repeat("a", 30_000), http.StatusFound)
		}))
		defer srv.Close()

		obs := probe(t, newProber(t, func(o *Options) { o.Retries = -1 }), endpointFor(t, srv.URL, ""))

		for _, r := range obs.Redirects {
			assert.True(t, len(r.URL) <= maxURL)
		}
	})
}

func Test_Options_zero_scope_errors_wrap(t *testing.T) {
	_, err := New(Options{}).Probe(context.Background(), model.Endpoint{
		Scheme: "http",
		Key:    model.AssetKey{IP: netip.MustParseAddr("127.0.0.1"), Port: 80},
	})
	assert.True(t, errors.Is(err, ErrNotAllowed))
	_ = url.URL{}
}
