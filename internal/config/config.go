// Package config loads runtime configuration from RAMPART_* environment
// variables. Load never touches the process environment or the network: the
// environment is injected and host names are resolved by ResolveAllowHosts.
package config

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Defaults kept from the prototype.
const (
	DefaultHTTPAddr          = ":9080"
	DefaultMaxRate           = 5000
	DefaultAllPortsMaxAddrs  = 16
	DefaultPathProbesPerHost = 50
	DefaultSecretsDir        = "/var/lib/ramparteye/secrets"
	DefaultDojoProductType   = "RampartEye"
	DefaultDojoEngagement    = "Continuous discovery"
)

// Config is the process configuration. There is no default scan scope:
// an empty AllowedCIDRs means every scan and target import is refused.
type Config struct {
	DatabaseURL    string         // RAMPART_DATABASE_URL
	HTTPAddr       string         // RAMPART_HTTP_ADDR, default :9080
	AllowedCIDRs   []netip.Prefix // RAMPART_ALLOWED_CIDRS, comma separated; empty = nothing may be scanned
	SecretKey      []byte         `json:"-"` // RAMPART_SECRET_KEY, optional, 64 hex chars (32 bytes)
	SecretsDir     string         // RAMPART_SECRETS_DIR, default /var/lib/ramparteye/secrets
	NmapPath       string         // RAMPART_NMAP_PATH, default "nmap"
	ScanPrivileged bool           // RAMPART_SCAN_PRIVILEGED: use -sS instead of -sT
	Demo           bool           // RAMPART_DEMO
	ScanExclude    []netip.Addr   // RAMPART_SCAN_EXCLUDE, addresses never scanned
	MaxRate        int            // RAMPART_MAX_RATE, packets/s upper bound, default 5000
	ScanPorts      []int          // RAMPART_SCAN_PORTS, allowed TCP ports; empty = no restriction
	Unstable       UnstableConfig
	TickEvery      time.Duration // RAMPART_TICK_EVERY, scheduler tick, default 1m

	// TrustedProxies are reverse proxies whose X-Forwarded-For is believed
	// for the client address (RAMPART_TRUSTED_PROXIES, CIDRs or IPs; empty =
	// the header is ignored).
	TrustedProxies []netip.Prefix

	// AllowHosts are host names from RAMPART_ALLOW_HOSTS. Load does not
	// resolve them; call ResolveAllowHosts to turn them into prefixes.
	AllowHosts []string

	// AllPortsMaxAddrs: the "auto" port profile scans all TCP ports when the
	// targets total at most this many addresses (RAMPART_ALL_PORTS_MAX_ADDRS; 0 disables).
	AllPortsMaxAddrs int
	HTTPTimeout      time.Duration // RAMPART_HTTP_TIMEOUT, default 10s
	HTTPRetries      int           // RAMPART_HTTP_RETRIES, 0-3, default 1
	// PathProbesPerHost is the signature path probes allowed per host per
	// run (RAMPART_PATH_PROBES_PER_HOST, default 50; 0 = no path probes).
	PathProbesPerHost int

	DojoURL         string // RAMPART_DOJO_URL (empty = DefectDojo disabled)
	DojoToken       string `json:"-"` // RAMPART_DOJO_TOKEN
	DojoProductType string // RAMPART_DOJO_PRODUCT_TYPE, default "RampartEye"
	DojoProduct     string // RAMPART_DOJO_PRODUCT
	DojoEngagement  string // RAMPART_DOJO_ENGAGEMENT, default "Continuous discovery"

	DojoAutoPush     bool // RAMPART_DOJO_AUTO_PUSH, default true
	DojoCloseMissing bool // RAMPART_DOJO_CLOSE_MISSING, default false
}

// redacted returns c without methods and with secrets masked.
func (c Config) redacted() any {
	type plain Config
	p := plain(c)
	mask := func(set bool) string {
		if set {
			return "[redacted]"
		}
		return ""
	}
	p.DojoToken = mask(c.DojoToken != "")
	p.SecretKey = nil
	if len(c.SecretKey) > 0 {
		p.SecretKey = []byte("[redacted]")
	}
	return p
}

// String formats c with secrets (API token, secret key) masked.
func (c Config) String() string { return fmt.Sprintf("%+v", c.redacted()) }

// GoString is String for %#v.
func (c Config) GoString() string { return fmt.Sprintf("%#v", c.redacted()) }

// UnstableConfig defines host instability across runs.
type UnstableConfig struct {
	InactiveAfterMisses int // RAMPART_INACTIVE_AFTER_MISSES, default 3
	UnstableIfFlips     int // RAMPART_UNSTABLE_IF_FLIPS, default 2
	Window              int // RAMPART_UNSTABLE_WINDOW, default 5 runs
}

// Resolver resolves a host name to IP addresses.
type Resolver func(ctx context.Context, host string) ([]netip.Addr, error)

// DefaultResolver uses the system resolver.
func DefaultResolver(ctx context.Context, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

// Load reads the configuration through env (typically os.Getenv).
func Load(env func(string) string) (Config, error) {
	str := func(k, def string) string {
		if v := env(k); v != "" {
			return v
		}
		return def
	}
	num := func(k string, def int) (int, error) {
		v := env(k)
		if v == "" {
			return def, nil
		}
		n, err := strconv.Atoi(v)
		if err != nil {
			return 0, fmt.Errorf("%s: %w", k, err)
		}
		return n, nil
	}
	flagDef := func(k string, def bool) (bool, error) {
		v := env(k)
		if v == "" {
			return def, nil
		}
		b, err := strconv.ParseBool(v)
		if err != nil {
			return false, fmt.Errorf("%s: %w", k, err)
		}
		return b, nil
	}
	flag := func(k string) (bool, error) { return flagDef(k, false) }
	dur := func(k, def string) (time.Duration, error) {
		d, err := time.ParseDuration(str(k, def))
		if err != nil {
			return 0, fmt.Errorf("%s: %w", k, err)
		}
		return d, nil
	}

	c := Config{
		DatabaseURL:     str("RAMPART_DATABASE_URL", "postgres://ramparteye:ramparteye@localhost:5432/ramparteye?sslmode=disable"),
		HTTPAddr:        str("RAMPART_HTTP_ADDR", DefaultHTTPAddr),
		SecretsDir:      str("RAMPART_SECRETS_DIR", DefaultSecretsDir),
		NmapPath:        str("RAMPART_NMAP_PATH", "nmap"),
		DojoURL:         env("RAMPART_DOJO_URL"),
		DojoToken:       env("RAMPART_DOJO_TOKEN"),
		DojoProductType: str("RAMPART_DOJO_PRODUCT_TYPE", DefaultDojoProductType),
		DojoProduct:     env("RAMPART_DOJO_PRODUCT"),
		DojoEngagement:  str("RAMPART_DOJO_ENGAGEMENT", DefaultDojoEngagement),
	}
	var err error
	if c.AllowedCIDRs, err = ParsePrefixes(env("RAMPART_ALLOWED_CIDRS")); err != nil {
		return c, fmt.Errorf("RAMPART_ALLOWED_CIDRS: %w", err)
	}
	if c.TrustedProxies, err = ParsePrefixes(env("RAMPART_TRUSTED_PROXIES")); err != nil {
		return c, fmt.Errorf("RAMPART_TRUSTED_PROXIES: %w", err)
	}
	for _, h := range strings.Split(env("RAMPART_ALLOW_HOSTS"), ",") {
		if h = strings.TrimSpace(h); h != "" {
			c.AllowHosts = append(c.AllowHosts, h)
		}
	}
	if c.AllPortsMaxAddrs, err = num("RAMPART_ALL_PORTS_MAX_ADDRS", DefaultAllPortsMaxAddrs); err != nil {
		return c, err
	}
	if c.ScanExclude, err = ParseAddrs(env("RAMPART_SCAN_EXCLUDE")); err != nil {
		return c, fmt.Errorf("RAMPART_SCAN_EXCLUDE: %w", err)
	}
	if c.MaxRate, err = num("RAMPART_MAX_RATE", DefaultMaxRate); err != nil {
		return c, err
	}
	if c.MaxRate < 1 {
		return c, fmt.Errorf("RAMPART_MAX_RATE must be at least 1")
	}
	if c.ScanPorts, err = ParsePorts(env("RAMPART_SCAN_PORTS")); err != nil {
		return c, fmt.Errorf("RAMPART_SCAN_PORTS: %w", err)
	}
	if c.ScanPrivileged, err = flag("RAMPART_SCAN_PRIVILEGED"); err != nil {
		return c, err
	}
	if c.Demo, err = flag("RAMPART_DEMO"); err != nil {
		return c, err
	}
	if c.DojoAutoPush, err = flagDef("RAMPART_DOJO_AUTO_PUSH", true); err != nil {
		return c, err
	}
	if c.DojoCloseMissing, err = flag("RAMPART_DOJO_CLOSE_MISSING"); err != nil {
		return c, err
	}
	if c.Unstable.InactiveAfterMisses, err = num("RAMPART_INACTIVE_AFTER_MISSES", 3); err != nil {
		return c, err
	}
	if c.Unstable.UnstableIfFlips, err = num("RAMPART_UNSTABLE_IF_FLIPS", 2); err != nil {
		return c, err
	}
	if c.Unstable.Window, err = num("RAMPART_UNSTABLE_WINDOW", 5); err != nil {
		return c, err
	}
	if c.Unstable.InactiveAfterMisses < 1 {
		return c, fmt.Errorf("RAMPART_INACTIVE_AFTER_MISSES must be at least 1")
	}
	if c.Unstable.UnstableIfFlips < 1 {
		return c, fmt.Errorf("RAMPART_UNSTABLE_IF_FLIPS must be at least 1")
	}
	if c.Unstable.Window < 1 {
		return c, fmt.Errorf("RAMPART_UNSTABLE_WINDOW must be at least 1")
	}
	if c.Unstable.Window < c.Unstable.UnstableIfFlips {
		return c, fmt.Errorf("RAMPART_UNSTABLE_WINDOW must be at least RAMPART_UNSTABLE_IF_FLIPS")
	}
	if c.AllPortsMaxAddrs < 0 {
		return c, fmt.Errorf("RAMPART_ALL_PORTS_MAX_ADDRS must not be negative")
	}
	if c.PathProbesPerHost, err = num("RAMPART_PATH_PROBES_PER_HOST", DefaultPathProbesPerHost); err != nil {
		return c, err
	}
	if c.PathProbesPerHost < 0 {
		return c, fmt.Errorf("RAMPART_PATH_PROBES_PER_HOST must not be negative")
	}
	if c.TickEvery, err = dur("RAMPART_TICK_EVERY", "1m"); err != nil {
		return c, err
	}
	if c.HTTPTimeout, err = dur("RAMPART_HTTP_TIMEOUT", "10s"); err != nil {
		return c, err
	}
	if c.HTTPTimeout <= 0 {
		return c, fmt.Errorf("RAMPART_HTTP_TIMEOUT: must be a positive duration such as 10s")
	}
	if c.HTTPRetries, err = num("RAMPART_HTTP_RETRIES", 1); err != nil {
		return c, err
	}
	if c.HTTPRetries < 0 || c.HTTPRetries > 3 {
		return c, fmt.Errorf("RAMPART_HTTP_RETRIES must be 0-3")
	}
	if k := env("RAMPART_SECRET_KEY"); k != "" {
		if c.SecretKey, err = parseHexKey(k); err != nil {
			return c, fmt.Errorf("RAMPART_SECRET_KEY: %w", err)
		}
	}
	return c, nil
}

// ResolveAllowHosts resolves hosts with resolve and returns each address as a
// single-address prefix (IPv4-mapped unmapped, zone dropped), deduplicated in
// first-seen order. A name that does not resolve is an error.
func ResolveAllowHosts(ctx context.Context, hosts []string, resolve Resolver) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, h := range hosts {
		addrs, err := resolve(ctx, h)
		if err != nil {
			return nil, fmt.Errorf("resolve %s: %w", h, err)
		}
		if len(addrs) == 0 {
			return nil, fmt.Errorf("resolve %s: no addresses", h)
		}
		for _, a := range addrs {
			a = a.Unmap().WithZone("")
			p := netip.PrefixFrom(a, a.BitLen())
			if !slices.Contains(out, p) {
				out = append(out, p)
			}
		}
	}
	return out, nil
}

// ParsePorts parses a TCP port list such as "22,80,443,8000-8100" into a
// sorted list without duplicates. An empty string gives nil.
func ParsePorts(s string) ([]int, error) {
	seen := map[int]bool{}
	var out []int
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		lo, hi, isRange := strings.Cut(part, "-")
		a, err := strconv.Atoi(strings.TrimSpace(lo))
		if err != nil || a < 1 || a > 65535 {
			return nil, fmt.Errorf("invalid port %q", part)
		}
		b := a
		if isRange {
			if b, err = strconv.Atoi(strings.TrimSpace(hi)); err != nil || b < a || b > 65535 {
				return nil, fmt.Errorf("invalid port range %q", part)
			}
		}
		for p := a; p <= b; p++ {
			if !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
		}
	}
	slices.Sort(out)
	return out, nil
}

// FormatPorts is the inverse of ParsePorts for a sorted list: "22,80,8000-8100".
func FormatPorts(ps []int) string {
	var b strings.Builder
	for i := 0; i < len(ps); {
		j := i
		for j+1 < len(ps) && ps[j+1] == ps[j]+1 {
			j++
		}
		if b.Len() > 0 {
			b.WriteByte(',')
		}
		b.WriteString(strconv.Itoa(ps[i]))
		if j > i {
			b.WriteByte('-')
			b.WriteString(strconv.Itoa(ps[j]))
		}
		i = j + 1
	}
	return b.String()
}

// ParsePrefixes parses a comma separated list of CIDRs or single IPs.
func ParsePrefixes(s string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if !strings.Contains(part, "/") {
			a, err := netip.ParseAddr(part)
			if err != nil {
				return nil, err
			}
			out = append(out, netip.PrefixFrom(a, a.BitLen()))
			continue
		}
		p, err := netip.ParsePrefix(part)
		if err != nil {
			return nil, err
		}
		out = append(out, p.Masked())
	}
	return out, nil
}

// ParseAddrs parses a comma separated list of IP addresses (IPv4-mapped
// addresses are unmapped).
func ParseAddrs(s string) ([]netip.Addr, error) {
	var out []netip.Addr
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		a, err := netip.ParseAddr(part)
		if err != nil {
			return nil, err
		}
		out = append(out, a.Unmap().WithZone(""))
	}
	return out, nil
}

func parseHexKey(s string) ([]byte, error) {
	if len(s) != 64 {
		return nil, fmt.Errorf("must be 64 hex characters (32 bytes)")
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("must be 64 hex characters")
	}
	return b, nil
}
