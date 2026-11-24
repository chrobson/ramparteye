package httpfp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ctx42/testing/pkg/assert"

	"github.com/chrobson/ramparteye/internal/model"
)

var icon = []byte("\x00\x00\x01\x00\x01\x00\x10\x10test-icon-bytes")

func Test_HTTPProber_Probe_redirects_title_cookies_favicon(t *testing.T) {
	var methods atomic.Value
	methods.Store("")
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		methods.Store(methods.Load().(string) + r.Method + " ")
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "pre", Value: "SECRET-1", HttpOnly: true})
		http.Redirect(w, r, "/a", http.StatusFound)
	})
	mux.HandleFunc("/a", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/login?next=%2F", http.StatusMovedPermanently)
	})
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{
			Name: "sid", Value: "SECRET-2", Secure: true, HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
		})
		w.Header().Set("Server", "TestServer/1.2")
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><head><TITLE>  Panel &amp; login
		</TITLE><link rel="shortcut icon" href="/static/i.ico"></head><body>x</body></html>`)
	})
	mux.HandleFunc("/static/i.ico", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/x-icon")
		_, _ = w.Write(icon)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	p := newProber(t, func(o *Options) { o.SkipFavicon = false })

	obs := probe(t, p, endpointFor(t, srv.URL, ""))

	assert.Equal(t, 200, obs.Status)
	assert.Equal(t, int64(7), obs.ServiceID)
	assert.True(t, strings.HasSuffix(obs.URL, "/login?next=%2F"))
	assert.Len(t, 2, obs.Redirects)
	assert.Equal(t, 302, obs.Redirects[0].Status)
	assert.Equal(t, 301, obs.Redirects[1].Status)
	assert.True(t, strings.HasSuffix(obs.Redirects[0].URL, "/"))
	assert.True(t, strings.HasSuffix(obs.Redirects[1].URL, "/a"))
	assert.Equal(t, "Panel & login", obs.Title)
	_, hasCookieHdr := obs.Headers["Set-Cookie"]
	assert.False(t, hasCookieHdr)
	assert.Equal(t, "TestServer/1.2", obs.Headers["Server"][0])
	assert.Len(t, 2, obs.Cookies)
	assert.Equal(t, "pre", obs.Cookies[0].Name)
	assert.True(t, obs.Cookies[0].HTTPOnly)
	want := model.Cookie{
		Name: "sid", Secure: true, HTTPOnly: true, SameSite: "Strict",
	}
	assert.Equal(t, want, obs.Cookies[1])
	sum := sha256.Sum256(obs.Body)
	assert.Equal(t, hex.EncodeToString(sum[:]), obs.BodySHA256)
	assert.True(t, len(obs.Body) > 0)
	if assert.NotNil(t, obs.FaviconMMH3) {
		assert.Equal(t, FaviconHash(icon), *obs.FaviconMMH3)
	}
	m := methods.Load().(string)
	assert.False(t, strings.Contains(m, "POST") || strings.Contains(m, "PUT"))
}

func Test_HTTPProber_Probe_redirect_limit(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := hits.Add(1)
		http.Redirect(w, r, "/r"+strconv.Itoa(int(n)), http.StatusFound)
	}))
	defer srv.Close()

	obs := probe(t, newProber(t, nil), endpointFor(t, srv.URL, ""))

	assert.Len(t, 5, obs.Redirects)
	assert.Equal(t, int32(6), hits.Load())
	assert.Equal(t, 302, obs.Status)
}

func Test_HTTPProber_Probe_cross_host_port_not_followed(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		http.Redirect(w, r, "http://127.0.0.1:6379/", http.StatusFound)
	}))
	defer srv.Close()

	obs := probe(t, newProber(t, nil), endpointFor(t, srv.URL, ""))

	assert.Equal(t, int32(1), hits.Load())
	assert.Len(t, 2, obs.Redirects)
	assert.Equal(t, "http://127.0.0.1:6379/", obs.Redirects[1].URL)
	assert.Equal(t, 0, obs.Redirects[1].Status)
}

func Test_HTTPProber_Probe_body_cap(t *testing.T) {
	t.Run("default 1 MiB, no error", func(t *testing.T) {
		big := bytes.Repeat([]byte("A"), 10<<20)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write(big)
		}))
		defer srv.Close()

		obs := probe(t, newProber(t, nil), endpointFor(t, srv.URL, ""))

		assert.Equal(t, 1<<20, len(obs.Body))
		assert.Equal(t, 200, obs.Status)
	})

	t.Run("larger option is clamped", func(t *testing.T) {
		big := bytes.Repeat([]byte("A"), 3<<20)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write(big)
		}))
		defer srv.Close()
		p := newProber(t, func(o *Options) { o.MaxBody = 10 << 20 })

		obs := probe(t, p, endpointFor(t, srv.URL, ""))

		assert.Equal(t, 1<<20, len(obs.Body))
	})
}

func Test_HTTPProber_Probe_favicon(t *testing.T) {
	t.Run("fallback to favicon.ico", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/favicon.ico" {
				_, _ = w.Write(icon)
				return
			}
			fmt.Fprint(w, "<html><title>x</title></html>")
		}))
		defer srv.Close()
		p := newProber(t, func(o *Options) { o.SkipFavicon = false })

		obs := probe(t, p, endpointFor(t, srv.URL, ""))

		if assert.NotNil(t, obs.FaviconMMH3) {
			assert.Equal(t, FaviconHash(icon), *obs.FaviconMMH3)
		}
	})

	t.Run("html soft-404 is not an icon", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, "<!doctype html><html><title>Not here</title></html>")
		}))
		defer srv.Close()
		p := newProber(t, func(o *Options) { o.SkipFavicon = false })

		obs := probe(t, p, endpointFor(t, srv.URL, ""))

		assert.Nil(t, obs.FaviconMMH3)
	})
}

func Test_HTTPProber_rate_limiter_shared(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()
	p := newProber(t, func(o *Options) { o.Rate = 25; o.Burst = 1 })
	ep := endpointFor(t, srv.URL, "")

	start := time.Now()
	for i := 0; i < 4; i++ {
		probe(t, p, ep)
	}

	assert.True(t, time.Since(start) >= 110*time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := p.Probe(ctx, ep)
	assert.Error(t, err)
}

func Test_New_defaults(t *testing.T) {
	p := New(Options{})

	assert.Equal(t, 10*time.Second, p.opt.Timeout)
	assert.Equal(t, 1, p.opt.Retries)
	assert.Equal(t, 20.0, p.opt.Rate)
	assert.Equal(t, 5, p.opt.Burst)
	assert.Equal(t, int64(1<<20), p.opt.MaxBody)
	assert.Equal(t, 5, p.limiter.Burst())
}

func Test_HTTPProber_Probe_invalid_endpoint(t *testing.T) {
	p := newProber(t, nil)

	_, err := p.Probe(context.Background(), model.Endpoint{Scheme: "http"})
	assert.Error(t, err)

	ep := model.Endpoint{
		Scheme: "ftp",
		Key:    model.AssetKey{IP: netip.MustParseAddr("127.0.0.1"), Port: 21},
	}
	_, err = p.Probe(context.Background(), ep)
	assert.Error(t, err)
}

func Test_HTTPProber_Probe_default_scheme_is_http(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	ep := endpointFor(t, srv.URL, "")
	ep.Scheme = ""

	obs := probe(t, newProber(t, nil), ep)

	assert.True(t, strings.HasPrefix(obs.URL, "http://127.0.0.1:"))
}

func Test_HTTPProber_Probe_error_is_not_ErrMethodNotAllowed(t *testing.T) {
	p := newProber(t, func(o *Options) { o.Retries = -1; o.Timeout = time.Second })
	ep := model.Endpoint{
		Scheme: "http",
		Key:    model.AssetKey{IP: netip.MustParseAddr("127.0.0.1"), Port: 1},
	}

	_, err := p.Probe(context.Background(), ep)

	assert.Error(t, err)
	assert.False(t, errors.Is(err, ErrMethodNotAllowed))
}
