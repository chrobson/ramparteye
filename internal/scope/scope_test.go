package scope

import (
	"net/netip"
	"testing"

	"github.com/ctx42/testing/pkg/assert"
)

func TestEmptyScopeRefusesEverything(t *testing.T) {
	s := mustNew(t, nil, nil, nil)

	assert.ErrorIs(t, ErrNoScope, s.CheckPrefix(netip.MustParsePrefix("10.0.0.0/24")))
	assert.False(t, s.Allows(netip.MustParseAddr("10.0.0.1")))
}

func TestPartialOverlapRefused(t *testing.T) {
	s := mustNew(t, []netip.Prefix{netip.MustParsePrefix("10.20.0.0/18")}, nil, nil)

	assert.ErrorIs(t, ErrOutOfScope, s.CheckPrefix(netip.MustParsePrefix("10.20.0.0/16")))
	assert.NoError(t, s.CheckPrefix(netip.MustParsePrefix("10.20.0.0/18")))
	assert.NoError(t, s.CheckPrefix(netip.MustParsePrefix("10.20.1.0/24")))
	assert.ErrorIs(t, ErrOutOfScope, s.CheckPrefix(netip.MustParsePrefix("10.20.64.0/24")))
}

func TestIPv4MappedIPv6(t *testing.T) {
	s := mustNew(t, []netip.Prefix{netip.MustParsePrefix("10.20.0.0/24")}, nil, nil)

	in := netip.MustParseAddr("::ffff:10.20.0.5")
	out := netip.MustParseAddr("::ffff:10.30.0.5")
	assert.True(t, s.Allows(in))
	assert.False(t, s.Allows(out))
	assert.NoError(t, s.CheckPrefix(netip.MustParsePrefix("::ffff:10.20.0.0/120")))
	assert.ErrorIs(t, ErrOutOfScope, s.CheckPrefix(netip.MustParsePrefix("::ffff:10.30.0.0/120")))
	// A wider IPv6 prefix that merely contains the mapped range is not inside.
	assert.ErrorIs(t, ErrOutOfScope, s.CheckPrefix(netip.MustParsePrefix("::ffff:0:0/80")))
}

func TestIPv6NotInIPv4Scope(t *testing.T) {
	s := mustNew(t, []netip.Prefix{netip.MustParsePrefix("10.20.0.0/24")}, nil, nil)

	assert.False(t, s.Allows(netip.MustParseAddr("2001:db8::1")))
	assert.False(t, s.Allows(netip.Addr{}))
}

func TestZoneStripped(t *testing.T) {
	s := mustNew(t, []netip.Prefix{netip.MustParsePrefix("fe80::/64")}, nil, nil)

	assert.True(t, s.Allows(netip.MustParseAddr("fe80::1%eth0")))
}

func TestExcludeWins(t *testing.T) {
	s := mustNew(t,
		[]netip.Prefix{netip.MustParsePrefix("10.20.0.0/24")},
		nil,
		[]netip.Addr{netip.MustParseAddr("10.20.0.5"), netip.MustParseAddr("::ffff:10.20.0.6")},
	)

	assert.False(t, s.Allows(netip.MustParseAddr("10.20.0.5")))
	assert.False(t, s.Allows(netip.MustParseAddr("::ffff:10.20.0.5")))
	assert.False(t, s.Allows(netip.MustParseAddr("10.20.0.6")))
	assert.True(t, s.Allows(netip.MustParseAddr("10.20.0.7")))
	// An exclusion inside a prefix does not invalidate the prefix.
	assert.NoError(t, s.CheckPrefix(netip.MustParsePrefix("10.20.0.0/24")))
}

func TestHostsAreSingleAddresses(t *testing.T) {
	s := mustNew(t, nil, []netip.Addr{netip.MustParseAddr("192.0.2.7")}, nil)

	assert.True(t, s.Allows(netip.MustParseAddr("192.0.2.7")))
	assert.False(t, s.Allows(netip.MustParseAddr("192.0.2.8")))
	assert.NoError(t, s.CheckPrefix(netip.MustParsePrefix("192.0.2.7/32")))
	assert.ErrorIs(t, ErrOutOfScope, s.CheckPrefix(netip.MustParsePrefix("192.0.2.0/24")))
}

func TestInvalidPrefixRefused(t *testing.T) {
	s := mustNew(t, []netip.Prefix{netip.MustParsePrefix("10.20.0.0/24")}, nil, nil)

	assert.ErrorIs(t, ErrOutOfScope, s.CheckPrefix(netip.Prefix{}))
}

func TestUnmaskedPrefixIsMasked(t *testing.T) {
	s := mustNew(t, []netip.Prefix{netip.MustParsePrefix("10.20.0.0/24")}, nil, nil)

	assert.NoError(t, s.CheckPrefix(netip.MustParsePrefix("10.20.0.77/25")))
}

func TestEmpty(t *testing.T) {
	assert.True(t, mustNew(t, nil, nil, nil).Empty())
	assert.True(t, Scope{}.Empty())
	assert.False(t, mustNew(t, nil, []netip.Addr{netip.MustParseAddr("192.0.2.7")}, nil).Empty())
}

func mustNew(t *testing.T, allowed []netip.Prefix, hosts, exclude []netip.Addr) Scope {
	t.Helper()
	s, err := New(allowed, hosts, exclude)
	assert.NoError(t, err)
	return s
}

func TestTranslationBlocksRefused(t *testing.T) {
	for _, scopeStr := range []string{"::/64", "::/0", "::ffff:0:0/80", "64:ff9b::/64"} {
		s := mustNew(t, []netip.Prefix{netip.MustParsePrefix(scopeStr)}, nil, nil)
		for _, q := range []string{"::ffff:0:0/95", "::/80", "::/0", "::ffff:0:0/80", "64:ff9b::/96", "64:ff9b::/120"} {
			assert.ErrorIs(t, ErrOutOfScope, s.CheckPrefix(netip.MustParsePrefix(q)), scopeStr+" "+q)
		}
		assert.False(t, s.Allows(netip.MustParseAddr("::ffff:8.8.8.8")))
		assert.False(t, s.Allows(netip.MustParseAddr("64:ff9b::808:808")))
	}
}

func TestIPv6ScopeStillWorks(t *testing.T) {
	s := mustNew(t, []netip.Prefix{netip.MustParsePrefix("2001:db8::/32")}, nil, nil)

	assert.NoError(t, s.CheckPrefix(netip.MustParsePrefix("2001:db8:1::/64")))
	assert.True(t, s.Allows(netip.MustParseAddr("2001:db8::1")))
}

func TestNewRejectsInvalidInputs(t *testing.T) {
	_, err := New(nil, nil, []netip.Addr{{}})
	assert.Error(t, err)
	_, err = New([]netip.Prefix{{}}, nil, nil)
	assert.Error(t, err)
	_, err = New(nil, []netip.Addr{{}}, nil)
	assert.Error(t, err)
}

func TestExcludedReturnsCopy(t *testing.T) {
	ex := netip.MustParseAddr("10.20.0.1")
	s := mustNew(t, []netip.Prefix{netip.MustParsePrefix("10.20.0.0/24")}, nil, []netip.Addr{ex})

	got := s.Excluded()
	assert.Equal(t, []netip.Addr{ex}, got)

	got[0] = netip.MustParseAddr("10.20.0.2")
	assert.Equal(t, []netip.Addr{ex}, s.Excluded())
}
