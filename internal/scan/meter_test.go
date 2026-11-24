package scan

import (
	"testing"

	"github.com/ctx42/testing/pkg/assert"
)

func TestMeteredArgs(t *testing.T) {
	in := []string{"-sn", "-n", "--max-rate", "300", "-oX", "-", "10.20.0.0/24", "10.20.1.5"}

	got := MeteredArgs(in)

	want := []string{"-v", "-sn", "-n", "--max-rate", "300", "-oX", "/dev/fd/3", "10.20.0.0/24", "10.20.1.5"}
	assert.Equal(t, want, got)
}

func TestParseRawPackets(t *testing.T) {
	out := "Read data files from: /usr/share/nmap\n" +
		"Nmap done: 1 IP address (1 host up) scanned in 0.06 seconds\n" +
		"           Raw packets sent: 3 (132B) | Rcvd: 6 (252B)\n"

	n, ok := ParseRawPackets(out)
	assert.True(t, ok)
	assert.Equal(t, int64(3), n)

	_, ok = ParseRawPackets("Nmap done")
	assert.False(t, ok)
}

func TestEstimatePackets(t *testing.T) {
	t.Run("connect adds one SYN per probed port", func(t *testing.T) {
		st := Stats{HostsTotal: 2, ScanType: "connect", NumServices: 100}
		assert.Equal(t, int64(207), EstimatePackets(st, nil, 7, true))
	})
	t.Run("syn uses raw counter", func(t *testing.T) {
		st := Stats{HostsTotal: 2, ScanType: "syn", NumServices: 100}
		assert.Equal(t, int64(150), EstimatePackets(st, nil, 150, true))
	})
	t.Run("discovery estimate", func(t *testing.T) {
		assert.Equal(t, int64(256*19), EstimatePackets(Stats{HostsTotal: 256}, []string{"-sn"}, 0, false))
	})
}
