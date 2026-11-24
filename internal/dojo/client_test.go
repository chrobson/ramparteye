package dojo

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/ctx42/testing/pkg/assert"
	"github.com/ctx42/testing/pkg/must"
)

const testToken = "s3cr3t-token"

// fakeDojo emulates the DefectDojo API v2 endpoints RampartEye uses.
type fakeDojo struct {
	mu       sync.Mutex
	calls    []string
	form     map[string]string
	file     []byte
	profile  string
	products int
}

const superProfile = `{"user":{"username":"scanner","is_superuser":true}}`

func newFake(t *testing.T) (*fakeDojo, *httptest.Server) {
	t.Helper()
	f := &fakeDojo{profile: superProfile, products: 1}
	authed := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			f.mu.Lock()
			f.calls = append(f.calls, r.Method+" "+r.URL.Path)
			f.mu.Unlock()
			if r.Header.Get("Authorization") != "Token "+testToken {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = io.WriteString(w, `{"detail":"Invalid token. `+testToken+`"}`)
				return
			}
			h(w, r)
		}
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v2/user_profile/", authed(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-DefectDojo-Version", "2.40.0")
		_, _ = io.WriteString(w, f.profile)
	}))
	mux.HandleFunc("GET /api/v2/products/", authed(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.form = map[string]string{"name_exact": r.URL.Query().Get("name_exact")}
		f.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]int{"count": f.products})
	}))
	mux.HandleFunc("POST /api/v2/reimport-scan/", authed(func(w http.ResponseWriter, r *http.Request) {
		must.Nil(r.ParseMultipartForm(1 << 20))
		form := map[string]string{}
		for k, v := range r.MultipartForm.Value {
			form[k] = v[0]
		}
		file, _, err := r.FormFile("file")
		must.Nil(err)
		body := must.Value(io.ReadAll(file))
		f.mu.Lock()
		f.form, f.file = form, body
		f.mu.Unlock()
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, `{"test":42,"test_id":42,"engagement_id":3,"product_id":2,"statistics":{"after":{"info":{"active":5}}}}`)
	}))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return f, srv
}

func goldenFile(t *testing.T) []byte {
	t.Helper()
	return must.Value(os.ReadFile(filepath.Join(testdataDir, "golden_findings.json")))
}

func TestCheckAllGreen(t *testing.T) {
	fake, srv := newFake(t)
	c := NewClient(srv.URL+"/", testToken, srv.Client())

	have, err := c.Check(context.Background(), "RampartEye")

	assert.NoError(t, err)
	assert.Equal(t, CheckResult{Reachable: true, TokenValid: true, CanImport: true, ProductExists: true,
		Version: "2.40.0", User: "scanner"}, have)
	assert.Equal(t, "RampartEye", fake.form["name_exact"])
}

func TestCheck401TokenInvalid(t *testing.T) {
	_, srv := newFake(t)
	c := NewClient(srv.URL, "wrong", srv.Client())

	have, err := c.Check(context.Background(), "RampartEye")

	assert.NoError(t, err)
	assert.Equal(t, CheckResult{Reachable: true, Version: ""}, have)
}

func TestCheckUnreachable(t *testing.T) {
	_, srv := newFake(t)
	srv.Close()
	c := NewClient(srv.URL, testToken, srv.Client())

	have, err := c.Check(context.Background(), "p")

	assert.Error(t, err)
	assert.False(t, have.Reachable)
	assert.NotContain(t, testToken, err.Error())
}

func TestCheckPermissionsAndProduct(t *testing.T) {
	cases := map[string]struct {
		profile string
		canImp  bool
	}{
		"reader only":     {`{"user":{"username":"r"},"product_member":[{"role":5}]}`, false},
		"no memberships":  {`{"user":{"username":"n"}}`, false},
		"writer":          {`{"user":{"username":"w"},"product_member":[{"role":3}]}`, true},
		"api importer":    {`{"user":{"username":"a"},"product_type_member":[{"role":4}]}`, true},
		"global maintain": {`{"user":{"username":"m"},"global_role":{"role":2}}`, true},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			fake, srv := newFake(t)
			fake.profile = tc.profile
			fake.products = 0

			have := must.Value(NewClient(srv.URL, testToken, srv.Client()).Check(context.Background(), "Nope"))

			assert.True(t, have.TokenValid)
			assert.Equal(t, tc.canImp, have.CanImport)
			assert.False(t, have.ProductExists)
		})
	}
}

func TestReimportSendsAutoCreateAndDedup(t *testing.T) {
	for _, closeOld := range []bool{true, false} {
		t.Run(map[bool]string{true: "close", false: "keep"}[closeOld], func(t *testing.T) {
			fake, srv := newFake(t)
			c := NewClient(srv.URL, testToken, srv.Client())
			file := goldenFile(t)

			have, err := c.Reimport(context.Background(), PushParams{Product: "Lab", Engagement: "e2e", TestTitle: "Weekly", CloseOldFindings: closeOld}, file)

			assert.NoError(t, err)
			assert.Equal(t, 42, have.ID())
			assert.Equal(t, 3, have.EngagementID)
			assert.Contain(t, `"after"`, string(have.Statistics))
			assert.Equal(t, []string{"POST /api/v2/reimport-scan/"}, fake.calls)
			want := map[string]string{
				"scan_type": "Generic Findings Import", "auto_create_context": "true",
				"deduplication_on_engagement": "true", "product_name": "Lab", "engagement_name": "e2e",
				"test_title": "Weekly", "product_type_name": "RampartEye",
				"close_old_findings": map[bool]string{true: "true", false: "false"}[closeOld],
			}
			for k, v := range want {
				assert.Equal(t, v, fake.form[k], k)
			}
			assert.Equal(t, string(file), string(fake.file))
		})
	}
}

func TestReimportDefaults(t *testing.T) {
	fake, srv := newFake(t)

	_, err := NewClient(srv.URL, testToken, srv.Client()).Reimport(context.Background(), PushParams{}, goldenFile(t))

	assert.NoError(t, err)
	assert.Equal(t, "RampartEye", fake.form["product_type_name"])
	assert.Equal(t, "RampartEye", fake.form["product_name"])
	assert.Equal(t, "Continuous discovery", fake.form["engagement_name"])
}

func TestReimportErrorsNeverLeakToken(t *testing.T) {
	_, srv := newFake(t)
	// The fake echoes the expected token in 401 bodies; the client token it
	// sent must still never appear in the error.
	c := NewClient(srv.URL, "other-"+testToken, srv.Client())

	_, err := c.Reimport(context.Background(), PushParams{}, goldenFile(t))

	var apiErr *APIError
	assert.ErrorAs(t, &apiErr, err)
	assert.Equal(t, 401, apiErr.Status)
	assert.NotContain(t, "other-"+testToken, err.Error())

	redacting := NewClient(srv.URL, testToken, srv.Client())
	assert.Equal(t, "x [redacted] y", redacting.redact("x "+testToken+" y"))
}

func TestReimportRefusals(t *testing.T) {
	_, srv := newFake(t)
	c := NewClient(srv.URL, testToken, srv.Client())
	ctx := context.Background()

	_, err := c.Reimport(ctx, PushParams{}, []byte(`{"findings":[{"title":"x"}]}`))
	assert.ErrorContain(t, "invalid file", err)

	_, err = c.Reimport(ctx, PushParams{}, make([]byte, MaxUploadBytes+1))
	assert.ErrorContain(t, "limit is", err)

	_, err = NewClient("ftp://x", testToken, nil).Reimport(ctx, PushParams{}, goldenFile(t))
	assert.ErrorContain(t, "http(s)", err)
}

func TestResponseSizeCap(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("a", MaxResponseBytes+10)))
	}))
	t.Cleanup(srv.Close)

	_, err := NewClient(srv.URL, testToken, srv.Client()).Check(context.Background(), "")

	assert.ErrorContain(t, "response larger than", err)
}

func TestNoCrossHostRedirectAndTokenNotForwarded(t *testing.T) {
	var mu sync.Mutex
	var otherAuth []string
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		otherAuth = append(otherAuth, r.Header.Get("Authorization"))
		mu.Unlock()
		_, _ = io.WriteString(w, `{"user":{"username":"evil"}}`)
	}))
	t.Cleanup(other.Close)
	// 127.0.0.1 vs localhost are different hosts for the redirect policy.
	target := strings.Replace(other.URL, "127.0.0.1", "localhost", 1)
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	t.Cleanup(first.Close)

	_, err := NewClient(first.URL, testToken, nil).Check(context.Background(), "")

	assert.ErrorContain(t, "another host", err)
	mu.Lock()
	defer mu.Unlock()
	assert.Len(t, 0, otherAuth)
	assert.NotContain(t, testToken, err.Error())
}

func TestSameHostRedirectKeepsToken(t *testing.T) {
	// Redirect within the same host: first server redirects to itself.
	self := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("hop") == "" {
			http.Redirect(w, r, r.URL.Path+"?hop=1", http.StatusTemporaryRedirect)
			return
		}
		assert.Equal(t, "Token "+testToken, r.Header.Get("Authorization"))
		_, _ = io.WriteString(w, superProfile)
	}))
	t.Cleanup(self.Close)

	have, err := NewClient(self.URL, testToken, nil).Check(context.Background(), "")

	assert.NoError(t, err)
	assert.True(t, have.TokenValid)
}

func TestTLSVerifiedByDefault(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, superProfile)
	}))
	t.Cleanup(srv.Close)

	// Default client does not trust the test certificate.
	_, err := NewClient(srv.URL, testToken, nil).Check(context.Background(), "")
	assert.Error(t, err)
	assert.NotContain(t, testToken, err.Error())

	// A custom CA pool makes the same server acceptable.
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	have, err := NewClient(srv.URL, testToken, NewHTTPClient(pool, 0)).Check(context.Background(), "")
	assert.NoError(t, err)
	assert.True(t, have.TokenValid)
}
