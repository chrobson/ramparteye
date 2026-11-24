// Package scope is the mandatory scan allowlist. Nothing is scanned or
// imported unless it lies inside the scope; an empty scope refuses everything.
package scope

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
)

var (
	// ErrNoScope is returned when no allowed networks or hosts are configured.
	ErrNoScope = errors.New("no scan scope configured (set RAMPART_ALLOWED_CIDRS)")
	// ErrOutOfScope is returned when an address or prefix is not fully inside
	// the scope, or is excluded.
	ErrOutOfScope = errors.New("outside the allowed scan scope")
)

// Scope is an immutable allowlist with a deny list of excluded addresses.
// The zero value has no scope and refuses everything.
type Scope struct {
	allowed []netip.Prefix
	exclude []netip.Addr
}

// New builds a scope from allowed prefixes, single allowed hosts and excluded
// addresses. All inputs are normalised (IPv4-mapped IPv6 unmapped, zones
// stripped, prefixes masked). An invalid (zero) prefix or address is an error:
// a dropped exclusion would silently widen what gets scanned.
func New(allowed []netip.Prefix, hosts []netip.Addr, exclude []netip.Addr) (Scope, error) {
	var s Scope
	for _, p := range allowed {
		n := normPrefix(p)
		if !n.IsValid() {
			return Scope{}, errors.New("scope: invalid allowed prefix")
		}
		s.allowed = append(s.allowed, n)
	}
	for _, a := range hosts {
		n := normAddr(a)
		if !n.IsValid() {
			return Scope{}, errors.New("scope: invalid allowed host")
		}
		s.allowed = append(s.allowed, netip.PrefixFrom(n, n.BitLen()))
	}
	for _, a := range exclude {
		n := normAddr(a)
		if !n.IsValid() {
			return Scope{}, errors.New("scope: invalid excluded address")
		}
		s.exclude = append(s.exclude, n)
	}
	return s, nil
}

// translation holds the IPv6 blocks that embed IPv4 space. An IPv6 scope must
// never grant IPv4 hosts through them: IPv4-mapped addresses are decided only
// via their IPv4 form, and NAT64 addresses are never allowed.
var translation = []netip.Prefix{
	netip.MustParsePrefix("::ffff:0:0/96"),
	netip.MustParsePrefix("64:ff9b::/96"),
}

// Allows reports whether a is inside the scope and not excluded.
func (s Scope) Allows(a netip.Addr) bool {
	a = normAddr(a)
	if !a.IsValid() || slices.Contains(s.exclude, a) || inTranslation(a) {
		return false
	}
	for _, p := range s.allowed {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// CheckPrefix returns nil only when the whole prefix lies inside one allowed
// prefix. Excluded addresses inside it do not make it invalid (they are passed
// to the scanner as exclusions). ErrNoScope is returned for an empty scope,
// ErrOutOfScope for anything else not fully covered.
func (s Scope) CheckPrefix(q netip.Prefix) error {
	if len(s.allowed) == 0 {
		return ErrNoScope
	}
	n := normPrefix(q)
	if !n.IsValid() {
		return fmt.Errorf("%w: invalid prefix", ErrOutOfScope)
	}
	if n.Addr().Is6() && inTranslation(n) {
		return fmt.Errorf("%w: %s overlaps an IPv4 translation block", ErrOutOfScope, n)
	}
	for _, p := range s.allowed {
		if p.Addr().Is4() == n.Addr().Is4() && p.Bits() <= n.Bits() && p.Contains(n.Addr()) {
			return nil
		}
	}
	return fmt.Errorf("%w: %s", ErrOutOfScope, n)
}

// inTranslation reports whether an IPv6 address or prefix (still IPv6 after
// normalisation) overlaps a translation block.
func inTranslation[T netip.Addr | netip.Prefix](x T) bool {
	for _, b := range translation {
		switch v := any(x).(type) {
		case netip.Addr:
			if v.Is6() && b.Contains(v) {
				return true
			}
		case netip.Prefix:
			if b.Overlaps(v) {
				return true
			}
		}
	}
	return false
}

func normAddr(a netip.Addr) netip.Addr {
	return a.WithZone("").Unmap()
}

// normPrefix unmaps IPv4-mapped prefixes (::ffff:a.b.c.d/96+n -> a.b.c.d/n),
// strips the zone and masks. Prefixes shorter than /96 stay IPv6 so that
// ::ffff:0:0/80 is never mistaken for an IPv4 range.
func normPrefix(p netip.Prefix) netip.Prefix {
	if !p.IsValid() {
		return netip.Prefix{}
	}
	a := p.Addr().WithZone("")
	bits := p.Bits()
	if a.Is4In6() && bits >= 96 {
		a, bits = a.Unmap(), bits-96
	}
	return netip.PrefixFrom(a, bits).Masked()
}

// Empty reports whether no scope is configured. Callers use it to avoid work
// (such as DNS lookups) that would be refused anyway.
func (s Scope) Empty() bool { return len(s.allowed) == 0 }

// Excluded returns a copy of the excluded addresses. Scanners pass them to
// nmap as exclusions.
func (s Scope) Excluded() []netip.Addr { return slices.Clone(s.exclude) }
