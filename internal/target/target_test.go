package target

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/chrobson/ramparteye/internal/model"
	"github.com/chrobson/ramparteye/internal/scope"
	"github.com/ctx42/testing/pkg/assert"
)

func fakeResolver(m map[string][]string) (Resolver, *int) {
	calls := 0
	return func(_ context.Context, host string) ([]netip.Addr, error) {
		calls++
		v, ok := m[host]
		if !ok {
			return nil, errors.New("no such host")
		}
		var out []netip.Addr
		for _, s := range v {
			out = append(out, netip.MustParseAddr(s))
		}
		return out, nil
	}, &calls
}

func labScope() scope.Scope {
	return scope.New([]netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")}, nil,
		[]netip.Addr{netip.MustParseAddr("10.20.0.99")})
}

func TestParseKinds(t *testing.T) {
	cases := []struct {
		in    string
		kind  model.TargetKind
		value string
	}{
		{"10.20.1.10", model.TargetIP, "10.20.1.10"},
		{"  10.20.1.10\t", model.TargetIP, "10.20.1.10"},
		{"::ffff:10.20.1.10", model.TargetIP, "10.20.1.10"},
		{"2001:DB8::1", model.TargetIP, "2001:db8::1"},
		{"10.20.0.0/24", model.TargetCIDR, "10.20.0.0/24"},
		{"10.20.0.77/24", model.TargetCIDR, "10.20.0.0/24"},
		{"10.20.1.10/32", model.TargetIP, "10.20.1.10"},
		{"::ffff:10.20.0.0/120", model.TargetCIDR, "10.20.0.0/24"},
		{"2001:db8::7/64", model.TargetCIDR, "2001:db8::/64"},
		{"10.0.0.1-10.0.0.5", model.TargetRange, "10.0.0.1-10.0.0.5"},
		{" 10.0.0.1 - 10.0.0.5 ", model.TargetRange, "10.0.0.1-10.0.0.5"},
		{"::ffff:10.0.0.1-::ffff:10.0.0.5", model.TargetRange, "10.0.0.1-10.0.0.5"},
		{"Example.COM.", model.TargetDomain, "example.com"},
		{"a-b.c1.lab", model.TargetDomain, "a-b.c1.lab"},
		{"LocalHost.", model.TargetDomain, "localhost"},
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			got, err := Parse(c.in)

			assert.NoError(t, err)
			assert.Equal(t, c.kind, got.Kind)
			assert.Equal(t, c.value, got.Value)
		})
	}
}

func TestParseErrors(t *testing.T) {
	cases := []struct {
		in  string
		err error
	}{
		{"", ErrEmpty},
		{"   ", ErrEmpty},
		{"10.20.0.300", ErrInvalidTarget},
		{"10.20.0.0/33", ErrInvalidTarget},
		{"10.20.0.0/", ErrInvalidTarget},
		{"fe80::1%eth0", ErrZone},
		{"2001:db8::zz", ErrInvalidTarget},
		{"10.0.0.5-10.0.0.1", ErrInvalidTarget},
		{"10.0.0.1-", ErrInvalidTarget},
		{"10.0.0.1-2001:db8::1", ErrInvalidTarget},
		{"2001:db8::1-2001:db8::9", ErrInvalidTarget},
		{"intranet", ErrInvalidDomain},
		{"foo_bar.com", ErrInvalidDomain},
		{"-foo.com", ErrInvalidDomain},
		{"foo..com", ErrInvalidDomain},
		{"foo.123", ErrInvalidDomain},
		{"http://example.com", ErrInvalidTarget},
		{strings.Repeat("a", 64) + ".com", ErrInvalidDomain},
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			_, err := Parse(c.in)

			assert.ErrorIs(t, c.err, err)
		})
	}
}

func TestNormalizeTags(t *testing.T) {
	got, err := NormalizeTags([]string{" Web ", "web", "", "Lab"})
	assert.NoError(t, err)
	assert.Equal(t, []string{"web", "lab"}, got)

	_, err = NormalizeTags([]string{"=cmd"})
	assert.Error(t, err)
	_, err = NormalizeTags([]string{"a;b"})
	assert.Error(t, err)
	_, err = NormalizeTags([]string{strings.Repeat("x", MaxTagLen+1)})
	assert.Error(t, err)
}

func TestResolveDomainInScope(t *testing.T) {
	r, _ := fakeResolver(map[string][]string{"app.lab": {"10.20.1.5", "::ffff:10.20.1.6"}})
	tg, _ := Parse("app.lab")

	got, err := Resolve(context.Background(), tg, r, labScope())

	assert.NoError(t, err)
	assert.Equal(t, []netip.Addr{netip.MustParseAddr("10.20.1.5"), netip.MustParseAddr("10.20.1.6")}, got)
}

func TestResolveDomainOutOfScope(t *testing.T) {
	cases := map[string][]string{
		"public":     {"8.8.8.8"},
		"one bad":    {"10.20.1.5", "8.8.8.8"},
		"ipv6":       {"2001:db8::1"},
		"mapped out": {"::ffff:8.8.8.8"},
		"excluded":   {"10.20.0.99"},
	}
	for name, addrs := range cases {
		t.Run(name, func(t *testing.T) {
			r, _ := fakeResolver(map[string][]string{"app.lab": addrs})
			tg, _ := Parse("app.lab")

			_, err := Resolve(context.Background(), tg, r, labScope())

			assert.ErrorIs(t, scope.ErrOutOfScope, err)
		})
	}
}

func TestResolveEmptyScopeNoLookup(t *testing.T) {
	r, calls := fakeResolver(map[string][]string{"app.lab": {"10.20.1.5"}})
	tg, _ := Parse("app.lab")

	_, err := Resolve(context.Background(), tg, r, scope.New(nil, nil, nil))

	assert.ErrorIs(t, scope.ErrNoScope, err)
	assert.Equal(t, 0, *calls)
}

func TestResolveNoAddressesAndLookupError(t *testing.T) {
	r, _ := fakeResolver(map[string][]string{"empty.lab": {}})

	tg, _ := Parse("empty.lab")
	_, err := Resolve(context.Background(), tg, r, labScope())
	assert.ErrorIs(t, ErrNoAddresses, err)

	tg, _ = Parse("missing.lab")
	_, err = Resolve(context.Background(), tg, r, labScope())
	assert.Error(t, err)
}

func TestResolveIPCIDRRange(t *testing.T) {
	s := labScope()
	ctx := context.Background()

	ip, _ := Parse("10.20.1.5")
	got, err := Resolve(ctx, ip, nil, s)
	assert.NoError(t, err)
	assert.Equal(t, []netip.Addr{netip.MustParseAddr("10.20.1.5")}, got)

	ip, _ = Parse("10.20.0.99")
	_, err = Resolve(ctx, ip, nil, s)
	assert.ErrorIs(t, scope.ErrOutOfScope, err)

	ip, _ = Parse("11.0.0.1")
	_, err = Resolve(ctx, ip, nil, s)
	assert.ErrorIs(t, scope.ErrOutOfScope, err)

	cidr, _ := Parse("10.20.0.0/24")
	_, err = Resolve(ctx, cidr, nil, s)
	assert.NoError(t, err)

	wide, _ := Parse("10.0.0.0/8")
	_, err = Resolve(ctx, wide, nil, s)
	assert.ErrorIs(t, scope.ErrOutOfScope, err)

	rng, _ := Parse("10.20.0.1-10.20.0.200")
	_, err = Resolve(ctx, rng, nil, s)
	assert.NoError(t, err)

	rng, _ = Parse("10.20.255.250-10.21.0.5")
	_, err = Resolve(ctx, rng, nil, s)
	assert.ErrorIs(t, scope.ErrOutOfScope, err)
}

func TestPrefixes(t *testing.T) {
	rng, _ := Parse("10.0.0.1-10.0.0.6")
	got, err := Prefixes(rng)
	assert.NoError(t, err)
	assert.Equal(t, []netip.Prefix{
		netip.MustParsePrefix("10.0.0.1/32"),
		netip.MustParsePrefix("10.0.0.2/31"),
		netip.MustParsePrefix("10.0.0.4/31"),
		netip.MustParsePrefix("10.0.0.6/32"),
	}, got)

	// Whole address space must not loop or overflow.
	all, _ := Parse("0.0.0.0-255.255.255.255")
	got, err = Prefixes(all)
	assert.NoError(t, err)
	assert.Equal(t, []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}, got)

	dom, _ := Parse("app.lab")
	_, err = Prefixes(dom)
	assert.Error(t, err)
}

func TestSplit24(t *testing.T) {
	got := Split([]netip.Prefix{netip.MustParsePrefix("10.20.0.0/22")}, 24)

	assert.Equal(t, []netip.Prefix{
		netip.MustParsePrefix("10.20.0.0/24"),
		netip.MustParsePrefix("10.20.1.0/24"),
		netip.MustParsePrefix("10.20.2.0/24"),
		netip.MustParsePrefix("10.20.3.0/24"),
	}, got)
}

func TestSplitKeepsSmallerAndClamps(t *testing.T) {
	small := netip.MustParsePrefix("10.20.0.0/28")
	assert.Equal(t, []netip.Prefix{small}, Split([]netip.Prefix{small}, 24))
	// bits beyond the family length are clamped: /30 -> four /32.
	assert.Len(t, 4, Split([]netip.Prefix{netip.MustParsePrefix("10.0.0.0/30")}, 99))
	// IPv6 /62 split to /64.
	assert.Len(t, 4, Split([]netip.Prefix{netip.MustParsePrefix("2001:db8::/62")}, 64))
}

func TestAddrCount(t *testing.T) {
	assert.Equal(t, uint64(256), AddrCount(netip.MustParsePrefix("10.0.0.0/24")))
	assert.Equal(t, uint64(1), AddrCount(netip.MustParsePrefix("10.0.0.1/32")))
	assert.Equal(t, uint64(1<<32), AddrCount(netip.MustParsePrefix("0.0.0.0/0")))
	assert.Equal(t, ^uint64(0), AddrCount(netip.MustParsePrefix("2001:db8::/32")))
}
