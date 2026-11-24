package httpfp

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ctx42/testing/pkg/assert"

	"github.com/chrobson/ramparteye/internal/model"
)

func Test_HTTPProber_Probe_records_response_time(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(300 * time.Millisecond)
		fmt.Fprint(w, "<title>slow</title>")
	}))
	defer srv.Close()

	obs := probe(t, newProber(t, nil), endpointFor(t, srv.URL, ""))

	assert.True(t, obs.ResponseMS >= 300 && obs.ResponseMS < 5000)
	assert.Equal(t, "slow", obs.Title)
}

func Test_HTTPProber_Probe_response_time_is_first_hop(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/slow", http.StatusFound)
	})
	mux.HandleFunc("/slow", func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(400 * time.Millisecond)
		fmt.Fprint(w, "ok")
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	obs := probe(t, newProber(t, nil), endpointFor(t, srv.URL, ""))

	assert.True(t, obs.ResponseMS > 0 && obs.ResponseMS < 400)
}

func Test_HTTPProber_Probe_retries_after_timeout(t *testing.T) {
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if n.Add(1) == 1 {
			time.Sleep(600 * time.Millisecond)
		}
		fmt.Fprint(w, "<title>second</title>")
	}))
	defer srv.Close()

	t.Run("one retry by default", func(t *testing.T) {
		p := newProber(t, func(o *Options) {
			o.Timeout = 300 * time.Millisecond
			o.RetryBackoff = time.Millisecond
		})

		obs := probe(t, p, endpointFor(t, srv.URL, ""))

		assert.Equal(t, "second", obs.Title)
		assert.Equal(t, int32(2), n.Load())
	})

	t.Run("retries disabled", func(t *testing.T) {
		n.Store(0)
		p := newProber(t, func(o *Options) {
			o.Timeout = 300 * time.Millisecond
			o.Retries = -1
		})

		_, err := p.Probe(context.Background(), endpointFor(t, srv.URL, ""))

		assert.Error(t, err)
		assert.Equal(t, int32(1), n.Load())
	})
}

func Test_HTTPProber_Probe_retries_dropped_connection(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	assert.NoError(t, err)
	defer ln.Close()
	var n atomic.Int32
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				if _, err := http.ReadRequest(bufio.NewReader(c)); err != nil {
					return
				}
				if n.Add(1) == 1 {
					return // hang up without a response
				}
				fmt.Fprint(c, "HTTP/1.1 200 OK\r\nContent-Length: 17\r\n"+
					"Content-Type: text/html\r\n\r\n<title>ok</title>")
			}(c)
		}
	}()
	p := newProber(t, func(o *Options) { o.RetryBackoff = time.Millisecond })

	obs := probe(t, p, endpointFor(t, "http://"+ln.Addr().String(), ""))

	assert.Equal(t, "ok", obs.Title)
	assert.Equal(t, int32(2), n.Load())
}

func Test_HTTPProber_Probe_slow_close(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	assert.NoError(t, err)
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				if _, err := http.ReadRequest(bufio.NewReader(c)); err != nil {
					return
				}
				fmt.Fprint(c, "HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\n"+
					"<title>closing slowly</title>")
				time.Sleep(500 * time.Millisecond)
			}(c)
		}
	}()

	obs := probe(t, newProber(t, nil), endpointFor(t, "http://"+ln.Addr().String(), ""))

	assert.Equal(t, "closing slowly", obs.Title)
	assert.True(t, obs.ResponseMS >= 500)
}

func Test_HTTPProber_Probe_refused_is_not_retried(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	assert.NoError(t, err)
	addr := ln.Addr().(*net.TCPAddr)
	ln.Close()
	var dials atomic.Int32
	d := &net.Dialer{Timeout: time.Second}
	p := newProber(t, func(o *Options) {
		o.RetryBackoff = time.Second
		o.DialContext = func(ctx context.Context, network, a string) (net.Conn, error) {
			dials.Add(1)
			return d.DialContext(ctx, network, a)
		}
	})
	ep := model.Endpoint{
		Scheme: "http",
		Key:    model.AssetKey{IP: netip.MustParseAddr("127.0.0.1"), Port: uint16(addr.Port), Proto: "tcp"},
	}

	start := time.Now()
	_, err = p.Probe(context.Background(), ep)

	assert.Error(t, err)
	assert.Equal(t, int32(1), dials.Load())
	assert.True(t, time.Since(start) < 900*time.Millisecond)
}

func Test_HTTPProber_Probe_latency_sample(t *testing.T) {
	t.Run("ignores cold start", func(t *testing.T) {
		var n atomic.Int32
		var mu sync.Mutex
		var methods []string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			methods = append(methods, r.Method)
			mu.Unlock()
			if n.Add(1) == 1 {
				time.Sleep(500 * time.Millisecond)
			}
			fmt.Fprint(w, "<title>warm</title>")
		}))
		defer srv.Close()
		p := newProber(t, func(o *Options) { o.LatencySample = true })

		obs := probe(t, p, endpointFor(t, srv.URL, ""))

		assert.True(t, obs.ResponseMS > 0 && obs.ResponseMS < 500)
		mu.Lock()
		defer mu.Unlock()
		assert.Equal(t, []string{"GET", "HEAD"}, methods)
	})

	t.Run("keeps an injected delay", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(300 * time.Millisecond)
			fmt.Fprint(w, "<title>slow</title>")
		}))
		defer srv.Close()
		p := newProber(t, func(o *Options) { o.LatencySample = true })

		obs := probe(t, p, endpointFor(t, srv.URL, ""))

		assert.True(t, obs.ResponseMS >= 300)
	})
}
