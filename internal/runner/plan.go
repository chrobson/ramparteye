package runner

import (
	"context"
	"fmt"
	"net/netip"
	"slices"

	"github.com/chrobson/ramparteye/internal/model"
	"github.com/chrobson/ramparteye/internal/scope"
	"github.com/chrobson/ramparteye/internal/target"
)

// Chunk sizes. Chunks are stored when a run is created and resumption works
// per chunk, so the size is fixed per run. IPv6 has its own size: the IPv4
// /24 would turn an IPv6 /112 into a single chunk of 65536 addresses.
const (
	DefaultChunkBits4 = 24
	DefaultChunkBits6 = 120
)

// Plan is the expansion of a profile's targets into scan chunks.
type Plan struct {
	Chunks    []netip.Prefix          // disjoint, sorted, only literal prefixes
	Hostnames map[netip.Addr][]string // names of domain targets per resolved address
	Skipped   []string                // "value: reason" for targets not scanned
}

// BuildPlan turns targets into disjoint chunks of at most /chunkBits for
// IPv4 (default /24) and /DefaultChunkBits6 for IPv6. Every target goes
// through target.Resolve: domains are resolved with r and refused as a whole
// when any address is outside s, IP/CIDR/range targets must lie fully inside
// s. With an empty scope every target is skipped and nothing is resolved.
// Domain names never reach the chunks, only their checked addresses.
func BuildPlan(ctx context.Context, targets []model.Target, s scope.Scope, r target.Resolver, chunkBits int) Plan {
	if chunkBits <= 0 || chunkBits > 32 {
		chunkBits = DefaultChunkBits4
	}
	p := Plan{Hostnames: map[netip.Addr][]string{}}
	var prefixes []netip.Prefix
	for _, t := range targets {
		addrs, err := target.Resolve(ctx, t, r, s)
		if err != nil {
			p.Skipped = append(p.Skipped, fmt.Sprintf("%s: %v", t.Value, err))
			continue
		}
		switch t.Kind {
		case model.TargetDomain:
			for _, a := range addrs {
				if !slices.Contains(p.Hostnames[a], t.Value) {
					p.Hostnames[a] = append(p.Hostnames[a], t.Value)
				}
				prefixes = append(prefixes, netip.PrefixFrom(a, a.BitLen()))
			}
		case model.TargetIP:
			prefixes = append(prefixes, netip.PrefixFrom(addrs[0], addrs[0].BitLen()))
		default:
			ps, err := target.Prefixes(t)
			if err != nil {
				p.Skipped = append(p.Skipped, fmt.Sprintf("%s: %v", t.Value, err))
				continue
			}
			prefixes = append(prefixes, ps...)
		}
	}
	for _, q := range dedupe(prefixes) {
		bits := chunkBits
		if q.Addr().Is6() {
			bits = DefaultChunkBits6
		}
		cs, err := target.Split([]netip.Prefix{q}, bits)
		if err == nil && len(p.Chunks)+len(cs) > target.MaxChunks {
			err = target.ErrTooManyChunks
		}
		if err != nil {
			p.Skipped = append(p.Skipped, fmt.Sprintf("%s: %v", q, err))
			continue
		}
		p.Chunks = append(p.Chunks, cs...)
	}
	return p
}

// dedupe sorts prefixes and drops those contained in another one.
func dedupe(ps []netip.Prefix) []netip.Prefix {
	ps = slices.Clone(ps)
	for i, q := range ps {
		ps[i] = q.Masked()
	}
	slices.SortFunc(ps, func(a, b netip.Prefix) int {
		if c := a.Addr().Compare(b.Addr()); c != 0 {
			return c
		}
		return a.Bits() - b.Bits()
	})
	var out []netip.Prefix
	for _, q := range ps {
		if n := len(out); n > 0 {
			last := out[n-1]
			if last.Addr().BitLen() == q.Addr().BitLen() && last.Bits() <= q.Bits() && last.Contains(q.Addr()) {
				continue
			}
		}
		out = append(out, q)
	}
	return out
}

// CountAddrs returns the number of addresses covered by the chunks,
// saturating at 1<<62.
func CountAddrs(chunks []netip.Prefix) uint64 {
	var n uint64
	for _, p := range chunks {
		host := p.Addr().BitLen() - p.Bits()
		if host >= 62 || n >= 1<<62 {
			return 1 << 62
		}
		n += 1 << host
	}
	return min(n, 1<<62)
}
