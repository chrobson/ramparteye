package httpfp

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/chrobson/ramparteye/internal/model"
)

// tlsInfo describes the leaf certificate and runs a separate verification
// (the handshake itself skipped verification to be able to read it).
func (p *HTTPProber) tlsInfo(cs *tls.ConnectionState, host string) *model.TLSInfo {
	if len(cs.PeerCertificates) == 0 {
		return &model.TLSInfo{Version: tls.VersionName(cs.Version), SANs: []string{}}
	}
	return CertInfo(cs.PeerCertificates, host, p.opt.Roots, p.opt.Now(), cs.Version)
}

// CertInfo builds TLSInfo for a presented chain (leaf first). host is the
// name or IP the client connected to; roots nil means system roots. Besides
// direct checks it runs a full x509 verification and maps its error onto the
// expired / self-signed / hostname-mismatch flags. Text fields come from the
// scanned host, so they are sanitised and bounded.
func CertInfo(chain []*x509.Certificate, host string, roots *x509.CertPool, now time.Time, version uint16) *model.TLSInfo {
	leaf := chain[0]
	info := &model.TLSInfo{
		Subject:   clean(leaf.Subject.String(), maxCertField),
		Issuer:    clean(leaf.Issuer.String(), maxCertField),
		NotBefore: leaf.NotBefore,
		NotAfter:  leaf.NotAfter,
		Version:   tls.VersionName(version),
		SANs:      []string{},
	}
	for _, d := range leaf.DNSNames {
		info.SANs = append(info.SANs, clean(d, maxCertField))
	}
	for _, ip := range leaf.IPAddresses {
		info.SANs = append(info.SANs, ip.String())
	}
	if len(info.SANs) > maxSANs {
		info.SANs = info.SANs[:maxSANs]
	}
	info.Expired = now.After(leaf.NotAfter)
	info.SelfSigned = selfSigned(leaf)
	if host != "" {
		info.Mismatch = leaf.VerifyHostname(host) != nil
	}

	inter := x509.NewCertPool()
	for _, c := range chain[1:] {
		inter.AddCert(c)
	}
	_, err := leaf.Verify(x509.VerifyOptions{
		DNSName:       host,
		Roots:         roots,
		Intermediates: inter,
		CurrentTime:   now,
	})
	var inv x509.CertificateInvalidError
	var hn x509.HostnameError
	var ua x509.UnknownAuthorityError
	switch {
	case errors.As(err, &inv) && inv.Reason == x509.Expired:
		// x509.Expired also covers "not yet valid"; only past expiry counts.
		if now.After(leaf.NotAfter) {
			info.Expired = true
		}
	case errors.As(err, &hn):
		info.Mismatch = true
	case errors.As(err, &ua):
		if len(chain) == 1 && bytes.Equal(leaf.RawIssuer, leaf.RawSubject) {
			info.SelfSigned = true
		}
	}
	return info
}

// selfSigned reports whether the certificate is issued by itself and its
// signature verifies with its own public key.
func selfSigned(c *x509.Certificate) bool {
	if !bytes.Equal(c.RawIssuer, c.RawSubject) {
		return false
	}
	return c.CheckSignatureFrom(c) == nil ||
		c.CheckSignature(c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature) == nil
}

// LegacyTLS is the result of an explicit TLS 1.0/1.1 handshake probe.
type LegacyTLS struct {
	TLS10       bool   `json:"tls10"`
	TLS11       bool   `json:"tls11"`
	TLS10Cipher string `json:"tls10_cipher,omitempty"`
	TLS11Cipher string `json:"tls11_cipher,omitempty"`
}

// legacyCipherSuites lists every suite Go can still negotiate on TLS <=1.1,
// including those removed from the defaults (RSA key exchange, 3DES, RC4):
// they are only offered when named in Config.CipherSuites.
func legacyCipherSuites() []uint16 {
	var ids []uint16
	for _, s := range tls.CipherSuites() {
		ids = append(ids, s.ID)
	}
	for _, s := range tls.InsecureCipherSuites() {
		ids = append(ids, s.ID)
	}
	return ids
}

// legacyClientConfig is the fallback when the default handshake fails: it
// accepts TLS 1.0+ and offers the legacy suites too.
func legacyClientConfig() *tls.Config {
	return &tls.Config{
		MinVersion:   tls.VersionTLS10,
		CipherSuites: legacyCipherSuites(),
	}
}

// isTLSHandshakeError reports errors that a legacy-TLS retry may fix.
func isTLSHandshakeError(err error) bool {
	var rec tls.RecordHeaderError
	if errors.As(err, &rec) {
		return false // the peer does not speak TLS at all
	}
	var alert tls.AlertError
	if errors.As(err, &alert) {
		return true
	}
	if errors.Is(err, io.EOF) {
		return true // some legacy stacks just hang up on a modern ClientHello
	}
	msg := err.Error()
	return strings.Contains(msg, "tls: ") || strings.Contains(msg, "remote error") ||
		strings.Contains(msg, "connection reset by peer")
}

// ProbeLegacyTLS attempts a bare handshake pinned to TLS 1.0 and then TLS
// 1.1. It only completes the handshake; no HTTP request is sent.
func (p *HTTPProber) ProbeLegacyTLS(ctx context.Context, ep model.Endpoint) (LegacyTLS, error) {
	var res LegacyTLS
	if !ep.Key.IP.IsValid() || ep.Key.Port == 0 {
		return res, errors.New("httpfp: endpoint without IP/port")
	}
	ip := ep.Key.IP.Unmap()
	if err := p.check(ip); err != nil {
		return res, err
	}
	t := endpointTarget(ip.String(), ep.Key.VHost)
	addr := net.JoinHostPort(t.ip, strconv.Itoa(int(ep.Key.Port)))
	var firstErr error
	for _, v := range []uint16{tls.VersionTLS10, tls.VersionTLS11} {
		cipher, err := p.handshake(ctx, addr, t.hostname, v)
		if err != nil {
			if firstErr == nil && ctx.Err() != nil {
				firstErr = ctx.Err()
			}
			continue
		}
		switch v {
		case tls.VersionTLS10:
			res.TLS10, res.TLS10Cipher = true, cipher
		case tls.VersionTLS11:
			res.TLS11, res.TLS11Cipher = true, cipher
		}
	}
	return res, firstErr
}

func (p *HTTPProber) handshake(ctx context.Context, addr, host string, version uint16) (string, error) {
	if err := p.wait(ctx); err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(ctx, p.opt.Timeout)
	defer cancel()
	raw, err := p.opt.DialContext(ctx, "tcp", addr)
	if err != nil {
		return "", err
	}
	defer raw.Close()
	cfg := &tls.Config{
		MinVersion:         version,
		MaxVersion:         version,
		CipherSuites:       legacyCipherSuites(),
		InsecureSkipVerify: true, //nolint:gosec // capability probe only
	}
	if _, err := netip.ParseAddr(host); err != nil {
		cfg.ServerName = host
	}
	conn := tls.Client(raw, cfg)
	if err := conn.HandshakeContext(ctx); err != nil {
		return "", err
	}
	cs := conn.ConnectionState()
	if cs.Version != version {
		return "", fmt.Errorf("negotiated %s", tls.VersionName(cs.Version))
	}
	return tls.CipherSuiteName(cs.CipherSuite), nil
}
