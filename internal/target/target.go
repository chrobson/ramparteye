// Package target parses, validates, resolves and chunks scan targets.
package target

import (
	"context"
	"errors"
	"fmt"
	"math"
	"math/bits"
	"net"
	"net/netip"
	"slices"
	"strings"

	"github.com/chrobson/ramparteye/internal/model"
	"github.com/chrobson/ramparteye/internal/scope"
)

// Parse errors. They are reported verbatim in import reports.
var (
	ErrEmpty         = errors.New("empty value")
	ErrInvalidTarget = errors.New("not a valid IP address, CIDR, range or domain")
	ErrZone          = errors.New("IPv6 zones are not allowed")
	ErrInvalidDomain = errors.New("invalid domain name")
	ErrNoAddresses   = errors.New("domain does not resolve to any address")
)

// Limits for tags and values.
const (
	MaxTagLen  = 64
	MaxTags    = 32
	maxDomain  = 253
	maxLabel   = 63
	maxValueSz = 512
)

// Resolver resolves a host name to addresses. Tests inject fakes so no DNS
// traffic is ever sent.
type Resolver func(ctx context.Context, host string) ([]netip.Addr, error)

// Parse classifies and normalises one target value:
//
//   - IP addresses are unmapped (::ffff:a.b.c.d -> a.b.c.d);
//   - CIDRs are masked; a full-length prefix collapses to a plain IP;
//   - IPv4 ranges "a-b" are written "a-b" with a <= b;
//   - domains follow RFC 1123, are lower-cased and lose a trailing dot.
//
// The returned target has no ID and no tags.
func Parse(raw string) (model.Target, error) {
	v := strings.TrimSpace(raw)
	if v == "" {
		return model.Target{}, ErrEmpty
	}
	if len(v) > maxValueSz {
		return model.Target{}, ErrInvalidTarget
	}
	if strings.Contains(v, "/") {
		p, err := netip.ParsePrefix(v)
		if err != nil {
			return model.Target{}, fmt.Errorf("%w: %s", ErrInvalidTarget, cleanErr(err))
		}
		if p.Addr().Zone() != "" {
			return model.Target{}, ErrZone
		}
		p = unmapPrefix(p).Masked()
		if p.IsSingleIP() {
			return model.Target{Kind: model.TargetIP, Value: p.Addr().String()}, nil
		}
		return model.Target{Kind: model.TargetCIDR, Value: p.String()}, nil
	}
	if a, err := netip.ParseAddr(v); err == nil {
		if a.Zone() != "" {
			return model.Target{}, ErrZone
		}
		return model.Target{Kind: model.TargetIP, Value: a.Unmap().String()}, nil
	}
	if lo, hi, ok := strings.Cut(v, "-"); ok {
		if t, ok, err := parseRange(lo, hi); ok {
			return t, err
		}
	}
	if looksNumeric(v) || strings.Contains(v, ":") {
		// "10.20.0.300" or a broken IPv6 literal: never treat it as a domain.
		return model.Target{}, ErrInvalidTarget
	}
	d, err := NormalizeDomain(v)
	if err != nil {
		return model.Target{}, err
	}
	return model.Target{Kind: model.TargetDomain, Value: d}, nil
}

// parseRange handles "a-b". ok is false when the left side is not an IP at
// all, so that host names with hyphens fall through to domain parsing.
func parseRange(lo, hi string) (model.Target, bool, error) {
	a, err := netip.ParseAddr(strings.TrimSpace(lo))
	if err != nil {
		return model.Target{}, false, nil
	}
	b, err := netip.ParseAddr(strings.TrimSpace(hi))
	if err != nil {
		return model.Target{}, true, ErrInvalidTarget
	}
	if a.Zone() != "" || b.Zone() != "" {
		return model.Target{}, true, ErrZone
	}
	a, b = a.Unmap(), b.Unmap()
	if !a.Is4() || !b.Is4() || a.Compare(b) > 0 {
		return model.Target{}, true, fmt.Errorf("%w: ranges are IPv4 only, first <= last", ErrInvalidTarget)
	}
	return model.Target{Kind: model.TargetRange, Value: a.String() + "-" + b.String()}, true, nil
}

// NormalizeDomain validates a host name per RFC 1123 and returns it
// lower-cased without a trailing dot. At least two labels are required except
// for "localhost".
func NormalizeDomain(s string) (string, error) {
	d := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), "."))
	if d == "" {
		return "", ErrInvalidDomain
	}
	if len(d) > maxDomain {
		return "", fmt.Errorf("%w: longer than %d characters", ErrInvalidDomain, maxDomain)
	}
	if d == "localhost" {
		return d, nil
	}
	labels := strings.Split(d, ".")
	if len(labels) < 2 {
		return "", fmt.Errorf("%w: a fully qualified name is required", ErrInvalidDomain)
	}
	for _, l := range labels {
		if err := checkLabel(l); err != nil {
			return "", fmt.Errorf("%w: %s", ErrInvalidDomain, err)
		}
	}
	if allDigits(labels[len(labels)-1]) {
		return "", fmt.Errorf("%w: numeric top-level label", ErrInvalidDomain)
	}
	return d, nil
}

func checkLabel(l string) error {
	switch {
	case l == "":
		return errors.New("empty label")
	case len(l) > maxLabel:
		return fmt.Errorf("label longer than %d characters", maxLabel)
	case l[0] == '-' || l[len(l)-1] == '-':
		return fmt.Errorf("label %q starts or ends with a hyphen", l)
	}
	for i := 0; i < len(l); i++ {
		c := l[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return fmt.Errorf("label %q contains a forbidden character", l)
		}
	}
	return nil
}

// NormalizeTags trims, lower-cases and dedupes tags, dropping empty ones. The
// order of first occurrence is kept so exports are stable.
func NormalizeTags(in []string) ([]string, error) {
	out := make([]string, 0, len(in))
	for _, t := range in {
		t = strings.ToLower(strings.TrimSpace(t))
		if t == "" || slices.Contains(out, t) {
			continue
		}
		if len(t) > MaxTagLen {
			return nil, fmt.Errorf("tag longer than %d characters", MaxTagLen)
		}
		if strings.ContainsAny(t[:1], "=+-@") {
			// Would be read as a formula when a CSV export is opened in a
			// spreadsheet (CSV injection).
			return nil, fmt.Errorf("tag %q must not start with = + - @", t)
		}
		for _, r := range t {
			if r < 0x20 || r == 0x7f || r == ';' || r == ',' {
				return nil, fmt.Errorf("tag %q contains a forbidden character", t)
			}
		}
		out = append(out, t)
	}
	if len(out) > MaxTags {
		return nil, fmt.Errorf("more than %d tags", MaxTags)
	}
	return out, nil
}

// SplitTags splits an "a;b;c" tag list (CSV and form format).
func SplitTags(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	return strings.Split(s, ";")
}

// Prefixes returns the prefixes covered by an IP, CIDR or range target. Domain
// targets have none and return an error.
func Prefixes(t model.Target) ([]netip.Prefix, error) {
	switch t.Kind {
	case model.TargetIP:
		a, err := netip.ParseAddr(t.Value)
		if err != nil {
			return nil, ErrInvalidTarget
		}
		a = a.Unmap()
		return []netip.Prefix{netip.PrefixFrom(a, a.BitLen())}, nil
	case model.TargetCIDR:
		p, err := netip.ParsePrefix(t.Value)
		if err != nil {
			return nil, ErrInvalidTarget
		}
		return []netip.Prefix{unmapPrefix(p).Masked()}, nil
	case model.TargetRange:
		lo, hi, _ := strings.Cut(t.Value, "-")
		a, err1 := netip.ParseAddr(lo)
		b, err2 := netip.ParseAddr(hi)
		if err1 != nil || err2 != nil || !a.Is4() || !b.Is4() || a.Compare(b) > 0 {
			return nil, ErrInvalidTarget
		}
		return rangePrefixes(a, b), nil
	}
	return nil, fmt.Errorf("%w: %s targets have no prefixes", ErrInvalidTarget, t.Kind)
}

// rangePrefixes covers [a, b] with the minimal list of IPv4 prefixes.
func rangePrefixes(a, b netip.Addr) []netip.Prefix {
	var out []netip.Prefix
	cur, end := uint64(addrU32(a)), uint64(addrU32(b))
	for cur <= end {
		size := uint64(1) << 32
		if cur != 0 {
			size = cur & -cur
		}
		for cur+size-1 > end {
			size >>= 1
		}
		out = append(out, netip.PrefixFrom(u32Addr(uint32(cur)), 32-bits.TrailingZeros64(size)))
		cur += size
	}
	return out
}

func addrU32(a netip.Addr) uint32 {
	b := a.As4()
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func u32Addr(v uint32) netip.Addr {
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

// Resolve checks t against the scope and returns the concrete addresses it
// names. IPs return themselves; domains are resolved with r (nil = system
// resolver) and EVERY resolved address must be inside the scope and not
// excluded, otherwise the whole target is refused with scope.ErrOutOfScope.
// CIDR and range targets are checked prefix by prefix and return no addresses
// (use Prefixes and Split to enumerate them). With an empty scope nothing is
// resolved and scope.ErrNoScope is returned.
func Resolve(ctx context.Context, t model.Target, r Resolver, s scope.Scope) ([]netip.Addr, error) {
	if s.Empty() {
		return nil, scope.ErrNoScope
	}
	if t.Kind != model.TargetDomain {
		ps, err := Prefixes(t)
		if err != nil {
			return nil, err
		}
		for _, p := range ps {
			if err := s.CheckPrefix(p); err != nil {
				return nil, err
			}
		}
		if t.Kind == model.TargetIP {
			if !s.Allows(ps[0].Addr()) {
				return nil, fmt.Errorf("%w: %s is excluded", scope.ErrOutOfScope, ps[0].Addr())
			}
			return []netip.Addr{ps[0].Addr()}, nil
		}
		return nil, nil
	}
	if r == nil {
		r = defaultResolver
	}
	addrs, err := r(ctx, t.Value)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", t.Value, err)
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("%w: %s", ErrNoAddresses, t.Value)
	}
	var out []netip.Addr
	for _, a := range addrs {
		a = a.WithZone("").Unmap()
		if !s.Allows(a) {
			return nil, fmt.Errorf("%w: %s resolves to %s", scope.ErrOutOfScope, t.Value, a)
		}
		if !slices.Contains(out, a) {
			out = append(out, a)
		}
	}
	return out, nil
}

func defaultResolver(ctx context.Context, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

// AddrCount returns the number of addresses in p, saturating at MaxUint64.
func AddrCount(p netip.Prefix) uint64 {
	host := p.Addr().BitLen() - p.Bits()
	if host >= 64 {
		return math.MaxUint64
	}
	return 1 << host
}

// Split cuts each prefix into prefixes of length bits (the scan chunk size,
// /24 by default). Prefixes already at least that specific are kept; bits
// larger than the address length is clamped to it. The caller bounds the
// input (scope-checked, so a /8 yields at most 65536 chunks of /24).
func Split(ps []netip.Prefix, bits int) []netip.Prefix {
	var out []netip.Prefix
	for _, p := range ps {
		p = p.Masked()
		want := min(max(bits, p.Bits()), p.Addr().BitLen())
		if want == p.Bits() {
			out = append(out, p)
			continue
		}
		for c := p.Addr(); p.Contains(c); {
			out = append(out, netip.PrefixFrom(c, want))
			next := lastAddr(netip.PrefixFrom(c, want)).Next()
			if !next.IsValid() {
				break
			}
			c = next
		}
	}
	return out
}

// lastAddr returns the last address of p.
func lastAddr(p netip.Prefix) netip.Addr {
	a := p.Addr().As16()
	bit := p.Bits()
	if p.Addr().Is4() {
		bit += 96
	}
	for i := bit; i < 128; i++ {
		a[i/8] |= 0x80 >> (i % 8)
	}
	last := netip.AddrFrom16(a)
	if p.Addr().Is4() {
		return last.Unmap()
	}
	return last
}

func unmapPrefix(p netip.Prefix) netip.Prefix {
	a := p.Addr()
	if !a.Is4In6() {
		return p
	}
	b := p.Bits() - 96
	if b < 0 {
		// ::ffff:0:0/80 and similar cover more than IPv4; keep IPv6 form.
		return p
	}
	return netip.PrefixFrom(a.Unmap(), b)
}

func looksNumeric(s string) bool {
	for i := 0; i < len(s); i++ {
		if !(s[i] >= '0' && s[i] <= '9' || s[i] == '.') {
			return false
		}
	}
	return true
}

func allDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return s != ""
}

// cleanErr strips the input echo from netip errors to keep reports short.
func cleanErr(err error) string {
	msg := err.Error()
	if i := strings.LastIndex(msg, ": "); i >= 0 {
		return msg[i+2:]
	}
	return msg
}
