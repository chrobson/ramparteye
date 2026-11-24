package scan

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/chrobson/ramparteye/internal/model"
	"github.com/chrobson/ramparteye/internal/scope"
)

// ErrDNSEnabled is returned when an nmap command line lacks -n: name
// resolution would let a scanned name rebind to an out-of-scope address.
var ErrDNSEnabled = errors.New("nmap command line does not disable DNS (-n)")

// Scanner discovers live hosts and their services. Implementations MUST
// re-check every operand against the scope right before exec.
type Scanner interface {
	// Discover returns live hosts in the given prefixes (phase 1, -sn) in
	// Result.Hosts.
	Discover(ctx context.Context, prefixes []netip.Prefix, o Opts) (Result, error)
	// Services returns open services with versions on live hosts (phase 2)
	// in Result.Services.
	Services(ctx context.Context, hosts []netip.Addr, o Opts) (Result, error)
}

// ExecFunc runs a command and returns its XML report. It is a seam for
// tests: unit tests replace it so nmap is never executed on the host.
type ExecFunc func(ctx context.Context, path string, args []string) ([]byte, error)

// Nmap implements Scanner by executing the nmap binary with XML output kept
// in memory. nmap only ever receives literal IP addresses and prefixes that
// were verified against the scope immediately before exec.
type Nmap struct {
	path    string
	scope   scope.Scope
	exclude []netip.Addr
	exec    ExecFunc // nil = run the real binary
}

var _ Scanner = (*Nmap)(nil)

// NewNmap returns an nmap-backed Scanner. An empty path means "nmap"; a nil
// exec runs the real binary. Addresses excluded by the scope are passed to
// nmap as --exclude and dropped from results.
func NewNmap(path string, s scope.Scope, exec ExecFunc) *Nmap {
	if path == "" {
		path = "nmap"
	}
	return &Nmap{path: path, scope: s, exclude: s.Excluded(), exec: exec}
}

// Discover runs phase 1 host discovery (-sn).
func (n *Nmap) Discover(ctx context.Context, prefixes []netip.Prefix, o Opts) (Result, error) {
	var out Result
	if len(prefixes) == 0 {
		return out, nil
	}
	for _, p := range prefixes {
		if err := n.scope.CheckPrefix(p); err != nil {
			return Result{}, err
		}
	}
	// nmap cannot mix IPv4 and IPv6 targets in one invocation (-6).
	for _, group := range splitPrefixesByFamily(prefixes) {
		res, err := n.run(ctx, DiscoveryArgs(group, o, familyAddrs(n.exclude, group[0].Addr().Unmap().Is6())))
		if err != nil {
			return Result{}, err
		}
		for _, h := range res.Hosts {
			if n.scope.Allows(h.IP) && inAny(h.IP, group) {
				out.Hosts = append(out.Hosts, h)
			}
		}
		out.Stats.add(res.Stats)
		out.Runs = append(out.Runs, res.Runs...)
	}
	sort.Slice(out.Hosts, func(i, j int) bool { return out.Hosts[i].IP.Less(out.Hosts[j].IP) })
	return out, nil
}

// Services runs phase 2 (port scan with light version detection) on hosts
// already known to be live.
func (n *Nmap) Services(ctx context.Context, hosts []netip.Addr, o Opts) (Result, error) {
	if n.scope.Empty() {
		return Result{}, scope.ErrNoScope
	}
	for _, h := range hosts {
		if !n.scope.Allows(h) && !slices.Contains(n.exclude, h.Unmap()) {
			return Result{}, fmt.Errorf("%w: %s", scope.ErrOutOfScope, h)
		}
	}
	hosts = n.filterExcluded(hosts)
	var out Result
	if len(hosts) == 0 {
		return out, nil
	}
	want := make(map[netip.Addr]bool, len(hosts))
	for _, h := range hosts {
		want[h] = true
	}
	// nmap cannot mix IPv4 and IPv6 targets in one invocation (-6).
	for _, group := range splitAddrsByFamily(hosts) {
		res, err := n.run(ctx, ServiceArgs(group, o))
		if err != nil {
			return Result{}, err
		}
		var svcs []model.ServiceObs
		seen := map[model.AssetKey]bool{}
		take := func(r Result) {
			for _, s := range r.Services {
				if want[s.Key.IP] && !seen[s.Key] {
					svcs = append(svcs, s)
					seen[s.Key] = true
				}
			}
		}
		take(res)
		out.merge(res, want)

		if len(o.ExtraPorts) > 0 && len(o.Ports) == 0 {
			extra, err := n.run(ctx, ExtraServiceArgs(group, o))
			if err != nil {
				return Result{}, err
			}
			take(extra)
			out.merge(Result{Stats: extra.Stats, Runs: extra.Runs}, want)
		}
		if o.DeepUnknown {
			if ports := DeepPorts(unknownPorts(svcs, group)); len(ports) > 0 {
				deep, err := n.run(ctx, DeepServiceArgs(group, ports, o))
				if err != nil {
					return Result{}, err
				}
				named := map[model.AssetKey]model.ServiceObs{}
				for _, s := range deep.Services {
					if want[s.Key.IP] && !unnamed(s) {
						named[s.Key] = s
					}
				}
				for i, s := range svcs {
					if d, ok := named[s.Key]; ok && unnamed(s) {
						svcs[i] = d
					}
				}
				out.merge(Result{Stats: deep.Stats, Runs: deep.Runs}, want)
			}
		}
		out.Services = append(out.Services, svcs...)
	}
	sort.Slice(out.Services, func(i, j int) bool { return keyLess(out.Services[i].Key, out.Services[j].Key) })
	sort.Slice(out.Hosts, func(i, j int) bool { return out.Hosts[i].IP.Less(out.Hosts[j].IP) })
	return out, nil
}

// merge folds r into the aggregate, keeping only wanted hosts and no
// services (callers collect services themselves).
func (r *Result) merge(o Result, want map[netip.Addr]bool) {
	for _, h := range o.Hosts {
		if want[h.IP] && !slices.ContainsFunc(r.Hosts, func(x model.HostObs) bool { return x.IP == h.IP }) {
			r.Hosts = append(r.Hosts, h)
		}
	}
	r.Stats.add(o.Stats)
	r.Runs = append(r.Runs, o.Runs...)
}

func (s *Stats) add(o Stats) {
	s.Elapsed += o.Elapsed
	s.HostsTotal += o.HostsTotal
	s.NumServices += o.NumServices
	if s.ScanType == "" {
		s.ScanType = o.ScanType
	}
}

// run vets the operands of args, executes nmap and parses its report.
func (n *Nmap) run(ctx context.Context, args []string) (Result, error) {
	targets, err := n.vet(args)
	if err != nil {
		return Result{}, err
	}
	start := time.Now()
	var (
		out  []byte
		raw  int64
		have bool
		argv = args
	)
	if n.exec != nil {
		out, err = n.exec(ctx, n.path, args)
	} else {
		argv = MeteredArgs(args)
		out, raw, have, err = runBinaryMetered(ctx, n.path, argv)
	}
	if err != nil {
		return Result{}, err
	}
	res, err := Parse(bytes.NewReader(out))
	if err != nil {
		return res, err
	}
	end := time.Now()
	elapsed := time.Duration(res.Stats.Elapsed * float64(time.Second))
	if elapsed <= 0 {
		elapsed = end.Sub(start)
	}
	res.Runs = []Run{{
		Argv:    argv,
		Targets: targets,
		Packets: EstimatePackets(res.Stats, args, raw, have),
		Raw:     have,
		Elapsed: elapsed,
		Start:   start,
		End:     end,
	}}
	return res, nil
}

// vet is the last gate before exec. It re-parses every target operand from
// the final argv and refuses (scope.ErrOutOfScope or scope.ErrNoScope) unless
// each one is a literal IP address or prefix inside the scope. Host names,
// zoned and IPv4-mapped addresses, options in operand position and anything
// else are refused, so nmap can never resolve a name itself.
func (n *Nmap) vet(args []string) ([]netip.Prefix, error) {
	if n.scope.Empty() {
		return nil, scope.ErrNoScope
	}
	if !slices.Contains(args, "-n") {
		return nil, ErrDNSEnabled
	}
	ops := operandArgs(args)
	if len(ops) == 0 {
		return nil, fmt.Errorf("%w: no target operands after -oX -", scope.ErrOutOfScope)
	}
	targets := make([]netip.Prefix, 0, len(ops))
	for _, op := range ops {
		p, err := n.vetOperand(op)
		if err != nil {
			return nil, err
		}
		targets = append(targets, p)
	}
	return targets, nil
}

func (n *Nmap) vetOperand(op string) (netip.Prefix, error) {
	if ip, err := netip.ParseAddr(op); err == nil {
		if ip.Zone() != "" || ip.Is4In6() {
			return netip.Prefix{}, fmt.Errorf("%w: %q is not a plain IP address", scope.ErrOutOfScope, op)
		}
		if !n.scope.Allows(ip) {
			return netip.Prefix{}, fmt.Errorf("%w: %s", scope.ErrOutOfScope, ip)
		}
		return netip.PrefixFrom(ip, ip.BitLen()), nil
	}
	if p, err := netip.ParsePrefix(op); err == nil {
		if p.Addr().Zone() != "" || p.Addr().Is4In6() {
			return netip.Prefix{}, fmt.Errorf("%w: %q is not a plain prefix", scope.ErrOutOfScope, op)
		}
		if err := n.scope.CheckPrefix(p); err != nil {
			return netip.Prefix{}, err
		}
		return p.Masked(), nil
	}
	return netip.Prefix{}, fmt.Errorf("%w: %q is not a literal IP address or prefix", scope.ErrOutOfScope, op)
}

func (n *Nmap) filterExcluded(hosts []netip.Addr) []netip.Addr {
	out := make([]netip.Addr, 0, len(hosts))
	for _, h := range hosts {
		if !slices.Contains(n.exclude, h.Unmap()) {
			out = append(out, h.Unmap())
		}
	}
	return out
}

// unnamed reports a service the version scan could not name.
func unnamed(s model.ServiceObs) bool {
	b := strings.TrimSuffix(s.Banner, "?")
	return s.Product == "" && (b == "" || b == "unknown" || b == "tcpwrapped")
}

// unknownPorts returns the sorted ports of unnamed services on the hosts of
// group.
func unknownPorts(svcs []model.ServiceObs, group []netip.Addr) []int {
	in := make(map[netip.Addr]bool, len(group))
	for _, h := range group {
		in[h.Unmap()] = true
	}
	set := map[int]bool{}
	for _, s := range svcs {
		if in[s.Key.IP.Unmap()] && s.Key.Proto == "tcp" && unnamed(s) {
			set[int(s.Key.Port)] = true
		}
	}
	ports := make([]int, 0, len(set))
	for p := range set {
		ports = append(ports, p)
	}
	sort.Ints(ports)
	return ports
}

// splitPrefixesByFamily returns the IPv4 group then the IPv6 group (each
// only when non-empty).
func splitPrefixesByFamily(ps []netip.Prefix) [][]netip.Prefix {
	var v4, v6 []netip.Prefix
	for _, p := range ps {
		if p.Addr().Unmap().Is6() {
			v6 = append(v6, p)
		} else {
			v4 = append(v4, p)
		}
	}
	var out [][]netip.Prefix
	for _, g := range [][]netip.Prefix{v4, v6} {
		if len(g) > 0 {
			out = append(out, g)
		}
	}
	return out
}

func splitAddrsByFamily(as []netip.Addr) [][]netip.Addr {
	var v4, v6 []netip.Addr
	for _, a := range as {
		if a.Unmap().Is6() {
			v6 = append(v6, a)
		} else {
			v4 = append(v4, a)
		}
	}
	var out [][]netip.Addr
	for _, g := range [][]netip.Addr{v4, v6} {
		if len(g) > 0 {
			out = append(out, g)
		}
	}
	return out
}

// familyAddrs keeps the addresses of one family (for --exclude).
func familyAddrs(as []netip.Addr, v6 bool) []netip.Addr {
	var out []netip.Addr
	for _, a := range as {
		if a.Unmap().Is6() == v6 {
			out = append(out, a.Unmap())
		}
	}
	return out
}

func inAny(ip netip.Addr, ps []netip.Prefix) bool {
	for _, p := range ps {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// runBinaryMetered executes a MeteredArgs command line: the XML is read from
// file descriptor 3 (in memory, never on disk, at most MaxOutputBytes) and
// the end of stdout is searched for nmap's "Raw packets sent: N" line. A
// cancelled or expired context kills the process and the context error is
// returned so callers can tell an interruption from a scan failure.
func runBinaryMetered(ctx context.Context, path string, args []string) ([]byte, int64, bool, error) {
	pr, pw, err := os.Pipe()
	if err != nil {
		return nil, 0, false, fmt.Errorf("nmap: pipe: %w", err)
	}
	defer func() { _ = pr.Close() }()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, args...)
	stdout := &tail{max: 8192}
	stderr := &capped{max: 4096}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	cmd.ExtraFiles = []*os.File{pw}
	cmd.WaitDelay = 5 * time.Second
	if err := cmd.Start(); err != nil {
		_ = pw.Close()
		return nil, 0, false, fmt.Errorf("nmap: %w", err)
	}
	_ = pw.Close()

	var xmlBuf bytes.Buffer
	overflow := false
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = io.Copy(&xmlBuf, io.LimitReader(pr, maxOutput+1))
		if int64(xmlBuf.Len()) > maxOutput {
			overflow = true
			cancel()
		}
	}()
	werr := cmd.Wait()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		_ = pr.Close()
		<-done
	}
	if overflow {
		return nil, 0, false, ErrOutputTooLarge
	}
	if err := runErr(ctx, werr, stderr); err != nil {
		return nil, 0, false, err
	}
	raw, ok := ParseRawPackets(stdout.String())
	return xmlBuf.Bytes(), raw, ok, nil
}

func runErr(ctx context.Context, err error, stderr *capped) error {
	if ctx.Err() != nil {
		return fmt.Errorf("nmap interrupted: %w", ctx.Err())
	}
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return fmt.Errorf("nmap exit %d: %s", ee.ExitCode(), strings.TrimSpace(stderr.String()))
		}
		return fmt.Errorf("nmap: %w", err)
	}
	return nil
}

// tail is a writer keeping only the last max bytes.
type tail struct {
	buf []byte
	max int
}

func (t *tail) Write(p []byte) (int, error) {
	t.buf = append(t.buf, p...)
	if over := len(t.buf) - t.max; over > 0 {
		t.buf = append(t.buf[:0], t.buf[over:]...)
	}
	return len(p), nil
}

func (t *tail) String() string { return string(t.buf) }

// capped is a writer keeping only the first max bytes.
type capped struct {
	buf bytes.Buffer
	max int
}

func (c *capped) Write(p []byte) (int, error) {
	if room := c.max - c.buf.Len(); room > 0 {
		c.buf.Write(p[:min(len(p), room)])
	}
	return len(p), nil
}

func (c *capped) String() string { return c.buf.String() }
