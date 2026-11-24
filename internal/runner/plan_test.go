package runner

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/ctx42/testing/pkg/assert"
	"github.com/ctx42/testing/pkg/must"

	"github.com/chrobson/ramparteye/internal/model"
	"github.com/chrobson/ramparteye/internal/scope"
)

func chunkList(p Plan) string {
	var out []string
	for _, c := range p.Chunks {
		out = append(out, c.String())
	}
	return strings.Join(out, " ")
}

func TestBuildPlan(t *testing.T) {
	resolve := func(_ context.Context, host string) ([]netip.Addr, error) {
		switch host {
		case "app.lab.local":
			return []netip.Addr{netip.MustParseAddr("10.20.30.40")}, nil
		case "dup.lab.local":
			return []netip.Addr{netip.MustParseAddr("10.20.0.10")}, nil // inside 10.20.0.0/22
		case "leak.lab.local":
			return []netip.Addr{netip.MustParseAddr("10.20.30.41"), netip.MustParseAddr("8.8.8.8")}, nil
		}
		return nil, errors.New("nxdomain")
	}
	targets := []model.Target{
		{Kind: model.TargetCIDR, Value: "10.20.0.0/22"},
		{Kind: model.TargetCIDR, Value: "10.20.1.0/24"}, // contained, dropped
		{Kind: model.TargetIP, Value: "10.20.1.7"},      // contained, dropped
		{Kind: model.TargetIP, Value: "10.20.50.1"},
		{Kind: model.TargetCIDR, Value: "10.20.60.0/30"},
		{Kind: model.TargetRange, Value: "10.20.61.1-10.20.61.2"},
		{Kind: model.TargetIP, Value: "192.168.1.1"},  // outside the scope
		{Kind: model.TargetCIDR, Value: "10.0.0.0/8"}, // larger than the scope
		{Kind: model.TargetDomain, Value: "app.lab.local"},
		{Kind: model.TargetDomain, Value: "dup.lab.local"},
		{Kind: model.TargetDomain, Value: "leak.lab.local"}, // one address outside: refused whole
		{Kind: model.TargetDomain, Value: "missing.lab.local"},
		{Kind: model.TargetIP, Value: "not-an-ip"},
	}
	p := BuildPlan(context.Background(), targets, labScope(), resolve, 0)
	assert.Equal(t, "10.20.0.0/24 10.20.1.0/24 10.20.2.0/24 10.20.3.0/24 10.20.30.40/32 "+
		"10.20.50.1/32 10.20.60.0/30 10.20.61.1/32 10.20.61.2/32", chunkList(p))
	assert.Equal(t, []string{"app.lab.local"}, p.Hostnames[netip.MustParseAddr("10.20.30.40")])
	assert.Equal(t, []string{"dup.lab.local"}, p.Hostnames[netip.MustParseAddr("10.20.0.10")])
	// 192.168.1.1, 10.0.0.0/8, leak.lab.local (10.20.30.41 is not scanned
	// either), missing.lab.local, not-an-ip.
	assert.Len(t, 5, p.Skipped)
	assert.Contain(t, "leak.lab.local", strings.Join(p.Skipped, "\n"))
}

func TestBuildPlanChunkSizes(t *testing.T) {
	lab := []model.Target{{Kind: model.TargetCIDR, Value: "10.20.0.0/18"}}
	assert.Len(t, 64, BuildPlan(context.Background(), lab, labScope(), nil, 24).Chunks)
	assert.Len(t, 16, BuildPlan(context.Background(), lab, labScope(), nil, 22).Chunks)
	assert.Len(t, 64, BuildPlan(context.Background(), lab, labScope(), nil, 99).Chunks) // invalid -> /24
}

// IPv6 uses its own chunk size (/120): the IPv4 /24 would make a /112 one
// chunk of 65536 addresses.
func TestBuildPlanIPv6Chunks(t *testing.T) {
	s := must.Value(scope.New([]netip.Prefix{pfx("2001:db8::/64")}, nil, nil))
	p := BuildPlan(context.Background(), []model.Target{{Kind: model.TargetCIDR, Value: "2001:db8::/112"}}, s, nil, 24)
	assert.Len(t, 256, p.Chunks)
	assert.Equal(t, pfx("2001:db8::/120"), p.Chunks[0])

	// A prefix that would split into more than target.MaxChunks is skipped.
	p = BuildPlan(context.Background(), []model.Target{{Kind: model.TargetCIDR, Value: "2001:db8::/64"}}, s, nil, 24)
	assert.Len(t, 0, p.Chunks)
	assert.Len(t, 1, p.Skipped)
}

func TestBuildPlanEmptyScope(t *testing.T) {
	calls := 0
	resolve := func(context.Context, string) ([]netip.Addr, error) {
		calls++
		return []netip.Addr{netip.MustParseAddr("10.20.0.1")}, nil
	}
	p := BuildPlan(context.Background(), []model.Target{
		{Kind: model.TargetCIDR, Value: "10.20.0.0/24"},
		{Kind: model.TargetDomain, Value: "app.lab.local"},
	}, scope.Scope{}, resolve, 24)
	assert.Len(t, 0, p.Chunks)
	assert.Len(t, 2, p.Skipped)
	assert.Equal(t, 0, calls) // no DNS traffic without a scope
}

// Excluded addresses are never chunks of their own; inside a CIDR they are
// left to the scanner's --exclude.
func TestBuildPlanExcludedAddress(t *testing.T) {
	s := must.Value(scope.New([]netip.Prefix{pfx("10.20.0.0/18")}, nil, []netip.Addr{netip.MustParseAddr("10.20.0.5")}))
	p := BuildPlan(context.Background(), []model.Target{
		{Kind: model.TargetIP, Value: "10.20.0.5"},
		{Kind: model.TargetIP, Value: "10.20.0.6"},
	}, s, nil, 24)
	assert.Equal(t, "10.20.0.6/32", chunkList(p))
	assert.Len(t, 1, p.Skipped)
}

func TestCountAddrs(t *testing.T) {
	ps := []netip.Prefix{pfx("127.0.0.1/32"), pfx("::1/128"), pfx("10.20.0.0/28")}
	assert.Equal(t, uint64(18), CountAddrs(ps))
	assert.Equal(t, uint64(1<<62), CountAddrs([]netip.Prefix{pfx("2001:db8::/32")}))
}
