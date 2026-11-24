package scan

import (
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/ctx42/testing/pkg/assert"
)

func TestDiscoveryArgs(t *testing.T) {
	got := DiscoveryArgs(
		[]netip.Prefix{netip.MustParsePrefix("10.20.0.0/24"), netip.MustParsePrefix("10.20.1.5/32")},
		Opts{MaxRate: 250},
		[]netip.Addr{netip.MustParseAddr("10.20.63.250")},
	)

	want := "-sn -n -PE -PS21,22,23,25,53,80,110,143,443,445,1883,3306,3389,5432,8080,8443 -PA80,443 " +
		"--max-rate 250 --exclude 10.20.63.250 -oX - 10.20.0.0/24 10.20.1.5"
	assert.Equal(t, want, strings.Join(got, " "))
}

func TestRateFlag(t *testing.T) {
	hosts := []netip.Addr{netip.MustParseAddr("10.20.0.10")}

	assert.True(t, slices.Contains(
		join(ServiceArgs(hosts, Opts{MaxRate: 800})), "--max-rate 800"))
	assert.Contain(t, "--max-rate 800", strings.Join(
		DiscoveryArgs([]netip.Prefix{netip.MustParsePrefix("10.20.0.0/24")}, Opts{MaxRate: 800}, nil), " "))
	assert.False(t, slices.Contains(ServiceArgs(hosts, Opts{}), "--max-rate"))
}

// join returns the adjacent-pair strings of args, so a flag and its value can
// be asserted together.
func join(args []string) []string {
	var out []string
	for i := 0; i+1 < len(args); i++ {
		out = append(out, args[i]+" "+args[i+1])
	}
	return out
}

func TestServiceArgs(t *testing.T) {
	hosts := []netip.Addr{netip.MustParseAddr("10.20.0.10"), netip.MustParseAddr("10.20.0.11")}

	t.Run("unprivileged", func(t *testing.T) {
		got := strings.Join(ServiceArgs(hosts, Opts{TopPorts: 100, MaxRate: 50}), " ")

		want := "-sT -Pn -n --top-ports 100 -sV --version-light --open --max-rate 50 -oX - 10.20.0.10 10.20.0.11"
		assert.Equal(t, want, got)
	})

	t.Run("privileged defaults", func(t *testing.T) {
		got := ServiceArgs(hosts, Opts{Privileged: true})

		assert.Equal(t, "-sS", got[0])
		assert.True(t, slices.Contains(got, "1000"))
		assert.False(t, slices.Contains(got, "--max-rate"))
	})
}

func TestServiceArgsExplicitPorts(t *testing.T) {
	hosts := []netip.Addr{netip.MustParseAddr("10.20.0.10")}

	got := strings.Join(ServiceArgs(hosts, Opts{TopPorts: 100, MaxRate: 50, Ports: []int{22, 80, 81, 82, 443}}), " ")

	want := "-sT -Pn -n -p 22,80-82,443 -sV --version-light --open --max-rate 50 -oX - 10.20.0.10"
	assert.Equal(t, want, got)
}

func TestServiceArgsAllPorts(t *testing.T) {
	all := allPortsForTest()

	got := strings.Join(ServiceArgs([]netip.Addr{netip.MustParseAddr("127.0.0.1")}, Opts{Ports: all}), " ")

	assert.Contain(t, " -p- ", got)
	assert.False(t, strings.Contains(got, "--top-ports"))
	assert.False(t, IsAllPorts(all[1:]))
	assert.False(t, IsAllPorts([]int{1, 65535}))
}

func TestExtraServiceArgs(t *testing.T) {
	hosts := []netip.Addr{netip.MustParseAddr("10.20.8.100")}

	got := strings.Join(ExtraServiceArgs(hosts, Opts{Privileged: true, MaxRate: 100, ExtraPorts: []int{1883, 6379}}), " ")

	want := "-sS -Pn -n -p 1883,6379 -sV --version-light --open --max-rate 100 -oX - 10.20.8.100"
	assert.Equal(t, want, got)
}

func TestIPv6ArgsUseSixFlag(t *testing.T) {
	got := ServiceArgs([]netip.Addr{netip.MustParseAddr("2001:db8::5")}, Opts{})

	assert.True(t, slices.Contains(got, "-6"))
	assert.Equal(t, "2001:db8::5", got[len(got)-1])
}

func allPortsForTest() []int {
	ps := make([]int, 65535)
	for i := range ps {
		ps[i] = i + 1
	}
	return ps
}
