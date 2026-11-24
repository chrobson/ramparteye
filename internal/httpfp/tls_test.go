package httpfp

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ctx42/testing/pkg/assert"
)

type certOpts struct {
	notBefore, notAfter time.Time
	dns                 []string
	ips                 []net.IP
	parent              *x509.Certificate
	parentKey           any
	isCA                bool
	rsa                 bool
}

func makeCert(t *testing.T, o certOpts) (*x509.Certificate, tls.Certificate, any) {
	t.Helper()
	var key, pub any
	if o.rsa {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		key, pub = k, &k.PublicKey
	} else {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		key, pub = k, &k.PublicKey
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "re-test", Organization: []string{"RE"}},
		NotBefore:    o.notBefore,
		NotAfter:     o.notAfter,
		DNSNames:     o.dns,
		IPAddresses:  o.ips,
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment |
			x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  o.isCA,
	}
	if o.isCA {
		tmpl.Subject.CommonName = "re-test-ca"
	}
	parent, signer := tmpl, key
	if o.parent != nil {
		parent, signer = o.parent, o.parentKey
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return c, tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: c}, key
}

func tlsServer(t *testing.T, cfg *tls.Config) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<title>secure</title>")
	}))
	srv.TLS = cfg
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func Test_HTTPProber_Probe_TLS(t *testing.T) {
	now := time.Now()
	lo := []net.IP{net.ParseIP("127.0.0.1")}

	t.Run("self-signed valid", func(t *testing.T) {
		_, kp, _ := makeCert(t, certOpts{
			notBefore: now.Add(-time.Hour), notAfter: now.Add(24 * time.Hour), ips: lo,
		})
		srv := tlsServer(t, &tls.Config{Certificates: []tls.Certificate{kp}})

		obs := probe(t, newProber(t, nil), endpointFor(t, srv.URL, ""))

		if !assert.NotNil(t, obs.TLS) {
			return
		}
		assert.True(t, obs.TLS.SelfSigned)
		assert.False(t, obs.TLS.Expired)
		assert.False(t, obs.TLS.Mismatch)
		assert.Equal(t, "secure", obs.Title)
		assert.True(t, obs.TLS.Version != "")
		assert.Equal(t, "127.0.0.1", obs.TLS.SANs[0])
	})

	t.Run("expired", func(t *testing.T) {
		_, kp, _ := makeCert(t, certOpts{
			notBefore: now.Add(-48 * time.Hour), notAfter: now.Add(-24 * time.Hour), ips: lo,
		})
		srv := tlsServer(t, &tls.Config{Certificates: []tls.Certificate{kp}})

		obs := probe(t, newProber(t, nil), endpointFor(t, srv.URL, ""))

		assert.True(t, obs.TLS.Expired)
		assert.True(t, obs.TLS.SelfSigned)
	})

	t.Run("hostname mismatch via vhost, CA-signed", func(t *testing.T) {
		ca, _, caKey := makeCert(t, certOpts{
			notBefore: now.Add(-time.Hour), notAfter: now.Add(time.Hour), isCA: true,
		})
		_, kp, _ := makeCert(t, certOpts{
			notBefore: now.Add(-time.Hour), notAfter: now.Add(time.Hour),
			dns: []string{"app.lab.test"}, parent: ca, parentKey: caKey,
		})
		srv := tlsServer(t, &tls.Config{Certificates: []tls.Certificate{kp}})
		roots := x509.NewCertPool()
		roots.AddCert(ca)
		p := newProber(t, func(o *Options) { o.Roots = roots })

		obs := probe(t, p, endpointFor(t, srv.URL, "app.lab.test"))

		assert.False(t, obs.TLS.Mismatch)
		assert.False(t, obs.TLS.SelfSigned)
		assert.False(t, obs.TLS.Expired)
		assert.True(t, strings.HasPrefix(obs.URL, "https://app.lab.test:"))

		obs = probe(t, p, endpointFor(t, srv.URL, "other.lab.test"))

		assert.True(t, obs.TLS.Mismatch)
		assert.False(t, obs.TLS.SelfSigned)
	})
}

func Test_HTTPProber_ProbeLegacyTLS(t *testing.T) {
	now := time.Now()
	_, kp, _ := makeCert(t, certOpts{
		notBefore: now.Add(-time.Hour), notAfter: now.Add(time.Hour), rsa: true,
		ips: []net.IP{net.ParseIP("127.0.0.1")},
	})
	p := newProber(t, nil)

	t.Run("legacy server", func(t *testing.T) {
		srv := tlsServer(t, &tls.Config{
			Certificates: []tls.Certificate{kp},
			MinVersion:   tls.VersionTLS10,
			MaxVersion:   tls.VersionTLS11,
			CipherSuites: []uint16{
				tls.TLS_RSA_WITH_AES_128_CBC_SHA, tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
			},
		})

		res, err := p.ProbeLegacyTLS(context.Background(), endpointFor(t, srv.URL, ""))

		assert.NoError(t, err)
		assert.True(t, res.TLS10)
		assert.True(t, res.TLS11)
		assert.True(t, res.TLS10Cipher != "")
	})

	t.Run("modern server", func(t *testing.T) {
		srv := tlsServer(t, &tls.Config{
			Certificates: []tls.Certificate{kp}, MinVersion: tls.VersionTLS12,
		})

		res, err := p.ProbeLegacyTLS(context.Background(), endpointFor(t, srv.URL, ""))

		assert.NoError(t, err)
		assert.False(t, res.TLS10)
		assert.False(t, res.TLS11)
	})

	t.Run("out of scope is never contacted", func(t *testing.T) {
		srv := tlsServer(t, &tls.Config{Certificates: []tls.Certificate{kp}})

		_, err := New(Options{}).ProbeLegacyTLS(context.Background(), endpointFor(t, srv.URL, ""))

		assert.ErrorIs(t, ErrNotAllowed, err)
	})
}

func Test_CertInfo_not_yet_valid_is_not_expired(t *testing.T) {
	now := time.Now()
	c, _, _ := makeCert(t, certOpts{
		notBefore: now.Add(time.Hour), notAfter: now.Add(2 * time.Hour), dns: []string{"a.test"},
	})

	info := CertInfo([]*x509.Certificate{c}, "a.test", nil, now, tls.VersionTLS13)

	assert.False(t, info.Expired)
	assert.False(t, info.Mismatch)
	assert.True(t, info.SelfSigned)
	assert.Equal(t, "TLS 1.3", info.Version)
}

func Test_CertInfo_hostile_fields_bounded(t *testing.T) {
	now := time.Now()
	var dns []string
	for i := 0; i < 300; i++ {
		dns = append(dns, fmt.Sprintf("h%d.test", i))
	}
	c, _, _ := makeCert(t, certOpts{
		notBefore: now.Add(-time.Hour), notAfter: now.Add(time.Hour), dns: dns,
	})
	c.Subject.CommonName = strings.Repeat("x", 5000)
	c.Issuer.CommonName = "bad\xff<script>"

	info := CertInfo([]*x509.Certificate{c}, "", nil, now, tls.VersionTLS12)

	assert.True(t, len(info.SANs) <= maxSANs)
	assert.True(t, len(info.Subject) <= maxCertField)
	assert.True(t, validUTF8(info.Issuer))
}

func Test_HTTPProber_Probe_falls_back_to_legacy_TLS(t *testing.T) {
	now := time.Now()
	_, kp, _ := makeCert(t, certOpts{
		notBefore: now.Add(-time.Hour), notAfter: now.Add(time.Hour), rsa: true,
		ips: []net.IP{net.ParseIP("127.0.0.1")},
	})
	srv := tlsServer(t, &tls.Config{
		Certificates: []tls.Certificate{kp},
		MinVersion:   tls.VersionTLS10,
		MaxVersion:   tls.VersionTLS10,
		CipherSuites: []uint16{tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA},
	})

	obs := probe(t, newProber(t, nil), endpointFor(t, srv.URL, ""))

	assert.True(t, obs.Status != 0)
	if assert.NotNil(t, obs.TLS) {
		assert.Equal(t, "TLS 1.0", obs.TLS.Version)
	}
}
