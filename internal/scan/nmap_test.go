package scan

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/chrobson/ramparteye/internal/scope"
	"github.com/ctx42/testing/pkg/assert"
	"github.com/ctx42/testing/pkg/must"
)

// fakeExec records every call and replays outs in order (the last repeats).
type fakeExec struct {
	calls [][]string
	outs  [][]byte
	err   error
}

func (f *fakeExec) run(_ context.Context, _ string, args []string) ([]byte, error) {
	f.calls = append(f.calls, args)
	if f.err != nil {
		return nil, f.err
	}
	return f.outs[min(len(f.calls)-1, len(f.outs)-1)], nil
}

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	return must.Value(os.ReadFile(filepath.Join("testdata", name)))
}

func newScope(t *testing.T, allowed []string, exclude ...string) scope.Scope {
	t.Helper()
	var ps []netip.Prefix
	for _, a := range allowed {
		ps = append(ps, netip.MustParsePrefix(a))
	}
	var ex []netip.Addr
	for _, a := range exclude {
		ex = append(ex, netip.MustParseAddr(a))
	}
	return must.Value(scope.New(ps, nil, ex))
}

func labScope(t *testing.T) scope.Scope {
	t.Helper()
	return newScope(t, []string{"10.20.0.0/18", "192.0.2.0/24"}, "10.20.63.250")
}

const emptyXML = `<?xml version="1.0"?><nmaprun><runstats><finished exit="success"/></runstats></nmaprun>`

func TestDiscoverFiltersAndScope(t *testing.T) {
	fe := &fakeExec{outs: [][]byte{fixture(t, "run1_discovery.xml")}}
	n := NewNmap("nmap", labScope(t), fe.run)
	req := netip.MustParsePrefix("10.20.0.0/22")

	res, err := n.Discover(context.Background(), []netip.Prefix{req}, Opts{})

	assert.NoError(t, err)
	hosts := res.UpHosts()
	for _, h := range hosts {
		assert.True(t, req.Contains(h), "host %s outside requested prefix", h)
	}
	assert.True(t, slices.Contains(hosts, netip.MustParseAddr("10.20.0.10")))
	assert.Len(t, 1, fe.calls)
}

func TestDiscoverRefusesOutOfScopeBeforeExec(t *testing.T) {
	fe := &fakeExec{outs: [][]byte{[]byte(emptyXML)}}
	n := NewNmap("nmap", labScope(t), fe.run)

	for _, p := range []string{"10.20.0.0/16", "8.8.8.8/32", "::ffff:8.8.8.8/128", "2001:db8::/32"} {
		_, err := n.Discover(context.Background(), []netip.Prefix{netip.MustParsePrefix(p)}, Opts{})
		assert.ErrorIs(t, scope.ErrOutOfScope, err, p)
	}

	assert.Len(t, 0, fe.calls)
}

func TestNoScopeRefusesEverything(t *testing.T) {
	fe := &fakeExec{outs: [][]byte{[]byte(emptyXML)}}
	n := NewNmap("nmap", scope.Scope{}, fe.run)

	_, err := n.Discover(context.Background(), []netip.Prefix{netip.MustParsePrefix("10.20.0.0/24")}, Opts{})
	assert.ErrorIs(t, scope.ErrNoScope, err)
	_, err = n.Services(context.Background(), []netip.Addr{netip.MustParseAddr("10.20.0.1")}, Opts{})
	assert.ErrorIs(t, scope.ErrNoScope, err)

	assert.Len(t, 0, fe.calls)
}

func TestExcludedAddrsPassedAsExclude(t *testing.T) {
	fe := &fakeExec{outs: [][]byte{[]byte(emptyXML)}}
	s := newScope(t, []string{"10.20.0.0/24"}, "10.20.0.1")
	n := NewNmap("nmap", s, fe.run)

	_, err := n.Discover(context.Background(), []netip.Prefix{netip.MustParsePrefix("10.20.0.0/24")}, Opts{})

	assert.NoError(t, err)
	assert.Len(t, 1, fe.calls)
	assert.Contain(t, "--exclude 10.20.0.1 ", strings.Join(fe.calls[0], " "))
}

func TestDiscoverDropsExcludedFromResult(t *testing.T) {
	xml := `<?xml version="1.0"?><nmaprun>` +
		`<host><status state="up"/><address addr="10.20.0.1" addrtype="ipv4"/></host>` +
		`<host><status state="up"/><address addr="10.20.0.2" addrtype="ipv4"/></host>` +
		`<host><status state="up"/><address addr="10.20.9.9" addrtype="ipv4"/></host>` +
		`</nmaprun>`
	fe := &fakeExec{outs: [][]byte{[]byte(xml)}}
	n := NewNmap("nmap", newScope(t, []string{"10.20.0.0/16"}, "10.20.0.1"), fe.run)

	res, err := n.Discover(context.Background(), []netip.Prefix{netip.MustParsePrefix("10.20.0.0/24")}, Opts{})

	assert.NoError(t, err)
	assert.Equal(t, []netip.Addr{netip.MustParseAddr("10.20.0.2")}, res.UpHosts())
	assert.Len(t, 1, res.Hosts)
}

func TestServicesScopeAndExclude(t *testing.T) {
	fe := &fakeExec{outs: [][]byte{fixture(t, "run1_services.xml")}}
	n := NewNmap("nmap", labScope(t), fe.run)
	ctx := context.Background()

	_, err := n.Services(ctx, []netip.Addr{netip.MustParseAddr("10.20.0.10"), netip.MustParseAddr("1.1.1.1")}, Opts{})
	assert.ErrorIs(t, scope.ErrOutOfScope, err)
	assert.Len(t, 0, fe.calls)

	// Only the excluded scanner itself: nothing to do.
	res, err := n.Services(ctx, []netip.Addr{netip.MustParseAddr("10.20.63.250")}, Opts{})
	assert.NoError(t, err)
	assert.Len(t, 0, res.Services)
	assert.Len(t, 0, fe.calls)

	res, err = n.Services(ctx, []netip.Addr{netip.MustParseAddr("10.20.0.10"), netip.MustParseAddr("10.20.0.11")}, Opts{})
	assert.NoError(t, err)
	// The fixture covers 27 hosts; results are restricted to the requested ones.
	assert.Len(t, 3, res.Services)
}

func TestExecErrorPropagates(t *testing.T) {
	fe := &fakeExec{err: context.DeadlineExceeded}
	n := NewNmap("", labScope(t), fe.run)

	_, err := n.Discover(context.Background(), []netip.Prefix{netip.MustParsePrefix("10.20.0.0/24")}, Opts{})

	assert.ErrorIs(t, context.DeadlineExceeded, err)
	assert.Equal(t, "nmap", n.path)
}

func TestMixedFamiliesRunSeparately(t *testing.T) {
	fe := &fakeExec{outs: [][]byte{[]byte(emptyXML)}}
	s := newScope(t, []string{"10.20.0.0/18", "2001:db8::/64"}, "10.20.63.250", "2001:db8::1")
	n := NewNmap("nmap", s, fe.run)
	ctx := context.Background()

	_, err := n.Discover(ctx, []netip.Prefix{
		netip.MustParsePrefix("2001:db8::100/120"), netip.MustParsePrefix("10.20.0.0/24"),
	}, Opts{})

	assert.NoError(t, err)
	assert.Len(t, 2, fe.calls)
	v4, v6 := strings.Join(fe.calls[0], " "), strings.Join(fe.calls[1], " ")
	assert.False(t, strings.Contains(v4, "-6") || strings.Contains(v4, "2001:db8"), v4)
	assert.Contain(t, "--exclude 10.20.63.250 ", v4)
	assert.Contain(t, " -6 ", v6)
	assert.False(t, strings.Contains(v6, "10.20."), v6)
	assert.Contain(t, "--exclude 2001:db8::1 ", v6)

	fe.calls = nil
	_, err = n.Services(ctx, []netip.Addr{netip.MustParseAddr("10.20.0.10"), netip.MustParseAddr("2001:db8::105")}, Opts{})
	assert.NoError(t, err)
	assert.Len(t, 2, fe.calls)
	assert.False(t, slices.Contains(fe.calls[0], "-6"))
	assert.True(t, slices.Contains(fe.calls[1], "-6"))
}

func TestExtraPortsPass(t *testing.T) {
	light := `<nmaprun><host><status state="up"/><address addr="10.20.0.7" addrtype="ipv4"/><ports>` +
		`<port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port></ports></host></nmaprun>`
	extra := `<nmaprun><host><status state="up"/><address addr="10.20.0.7" addrtype="ipv4"/><ports>` +
		`<port protocol="tcp" portid="6379"><state state="open"/><service name="redis"/></port></ports></host></nmaprun>`
	fe := &fakeExec{outs: [][]byte{[]byte(light), []byte(extra)}}
	n := NewNmap("nmap", labScope(t), fe.run)

	res, err := n.Services(context.Background(), []netip.Addr{netip.MustParseAddr("10.20.0.7")},
		Opts{ExtraPorts: []int{6379}})

	assert.NoError(t, err)
	assert.Len(t, 2, fe.calls)
	assert.Contain(t, "-p 6379 ", strings.Join(fe.calls[1], " "))
	assert.Len(t, 2, res.Services)
}

func TestExecRefusesOutOfScopeOperand(t *testing.T) {
	base := []string{"-sn", "-n", "-oX", "-"}
	tests := []struct {
		testN string

		args []string
		want error
	}{
		{"prefix outside scope", append(slices.Clone(base), "192.168.0.0/24"), scope.ErrOutOfScope},
		{"partial overlap", append(slices.Clone(base), "10.20.0.0/16"), scope.ErrOutOfScope},
		{"one bad among good", append(slices.Clone(base), "10.20.0.1", "8.8.8.8"), scope.ErrOutOfScope},
		{"excluded host", append(slices.Clone(base), "10.20.63.250"), scope.ErrOutOfScope},
		{"host name", append(slices.Clone(base), "internal.example.com"), scope.ErrOutOfScope},
		{"ipv4 mapped", append(slices.Clone(base), "::ffff:10.20.0.5"), scope.ErrOutOfScope},
		{"zoned address", append(slices.Clone(base), "fe80::1%eth0"), scope.ErrOutOfScope},
		{"option as operand", append(slices.Clone(base), "--script=evil"), scope.ErrOutOfScope},
		{"second output flag", append(slices.Clone(base), "10.20.0.1", "-oX", "-", "8.8.8.8"), scope.ErrOutOfScope},
		{"no operands", base, scope.ErrOutOfScope},
		{"no output flag", []string{"-sn", "-n", "8.8.8.8"}, scope.ErrOutOfScope},
		{"dns not disabled", []string{"-sn", "-oX", "-", "10.20.0.1"}, ErrDNSEnabled},
	}
	for _, tt := range tests {
		t.Run(tt.testN, func(t *testing.T) {
			fe := &fakeExec{outs: [][]byte{[]byte(emptyXML)}}
			n := NewNmap("nmap", labScope(t), fe.run)

			_, err := n.run(context.Background(), tt.args)

			assert.ErrorIs(t, tt.want, err)
			assert.Len(t, 0, fe.calls)
		})
	}

	t.Run("vetted operands reach exec", func(t *testing.T) {
		fe := &fakeExec{outs: [][]byte{[]byte(emptyXML)}}
		n := NewNmap("nmap", labScope(t), fe.run)

		_, err := n.run(context.Background(), append(slices.Clone(base), "10.20.0.0/24", "10.20.1.5"))

		assert.NoError(t, err)
		assert.Len(t, 1, fe.calls)
	})
}

func TestEveryBuilderPassesNoDNS(t *testing.T) {
	h := []netip.Addr{netip.MustParseAddr("10.20.0.1")}
	for _, args := range [][]string{
		DiscoveryArgs([]netip.Prefix{netip.MustParsePrefix("10.20.0.0/24")}, Opts{}, nil),
		ServiceArgs(h, Opts{}),
		ExtraServiceArgs(h, Opts{ExtraPorts: []int{1}}),
		DeepServiceArgs(h, []int{1}, Opts{}),
	} {
		assert.True(t, slices.Contains(args, "-n"), "%v", args)
	}
}

func TestRunBinaryInterrupted(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("sh not available")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, _, _, err = runBinaryMetered(ctx, sh, []string{"-c", "sleep 5"})

	assert.ErrorIs(t, context.Canceled, err)
}

func TestRunBinaryCapsOutput(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("sh not available")
	}

	maxOutput = 1 << 20
	defer func() { maxOutput = MaxOutputBytes }()

	_, _, _, err = runBinaryMetered(context.Background(), sh, []string{"-c", "exec yes >&3"})

	assert.True(t, errors.Is(err, ErrOutputTooLarge), "err = %v", err)
}

// TestRealNmapLocalhost runs nmap against 127.0.0.1 only (never a network)
// when it is installed: the XML must be read from fd 3 and parsed.
func TestRealNmapLocalhost(t *testing.T) {
	path, err := exec.LookPath("nmap")
	if err != nil {
		t.Skip("nmap not installed")
	}
	n := NewNmap(path, newScope(t, []string{"127.0.0.1/32"}), nil)

	res, err := n.Services(context.Background(), []netip.Addr{netip.MustParseAddr("127.0.0.1")},
		Opts{Ports: []int{1}, MaxRate: 50})

	assert.NoError(t, err)
	assert.Len(t, 1, res.Runs)
	assert.Equal(t, "-v", res.Runs[0].Argv[0])
	assert.Equal(t, []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}, res.Runs[0].Targets)
}
