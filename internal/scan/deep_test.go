package scan

import (
	"context"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/ctx42/testing/pkg/assert"
	"github.com/ctx42/testing/pkg/must"
)

const deepLightXML = `<?xml version="1.0"?><nmaprun><host><status state="up"/><address addr="10.20.0.7" addrtype="ipv4"/><ports>
<port protocol="tcp" portid="8787"><state state="open"/><service name="http" product="nginx" version="1.31.9"/></port>
<port protocol="tcp" portid="15432"><state state="open"/><service name="unknown"/></port>
<port protocol="tcp" portid="50000"><state state="open"/><service name="unknown"/></port>
</ports></host></nmaprun>`

const deepXML = `<?xml version="1.0"?><nmaprun><host><status state="up"/><address addr="10.20.0.7" addrtype="ipv4"/><ports>
<port protocol="tcp" portid="15432"><state state="open"/><service name="postgresql" product="PostgreSQL DB"/></port>
<port protocol="tcp" portid="50000"><state state="open"/><service name="unknown"/></port>
</ports></host></nmaprun>`

func TestDeepUnknownPass(t *testing.T) {
	host := []netip.Addr{netip.MustParseAddr("10.20.0.7")}

	t.Run("deep pass names unknown ports", func(t *testing.T) {
		fe := &fakeExec{outs: [][]byte{[]byte(deepLightXML), []byte(deepXML)}}
		n := NewNmap("nmap", labScope(t), fe.run)

		res, err := n.Services(context.Background(), host, Opts{Ports: allPortsForTest(), DeepUnknown: true})

		assert.NoError(t, err)
		assert.Len(t, 2, fe.calls)
		assert.Contain(t, "-p 15432,50000 -sV --version-intensity 4 --open", strings.Join(fe.calls[1], " "))
		got := map[uint16]string{}
		for _, s := range res.Services {
			got[s.Key.Port] = s.Product + "|" + s.Banner
		}
		want := map[uint16]string{15432: "PostgreSQL DB|postgresql", 8787: "nginx|http", 50000: "|unknown"}
		assert.Equal(t, want, got)
	})

	t.Run("no deep pass without the option", func(t *testing.T) {
		fe := &fakeExec{outs: [][]byte{[]byte(deepLightXML)}}
		n := NewNmap("nmap", labScope(t), fe.run)

		_, err := n.Services(context.Background(), host, Opts{Ports: allPortsForTest()})

		assert.NoError(t, err)
		assert.Len(t, 1, fe.calls)
		assert.False(t, slices.Contains(fe.calls[0], "--version-intensity"))
	})
}

func TestDeepPortsCap(t *testing.T) {
	ports := []int{2223, 15432}
	for p := 21000; p <= 21010; p++ { // FTP passive range
		ports = append(ports, p)
	}
	for p := 50000; p < 50040; p += 2 { // ephemeral, 20 ports
		ports = append(ports, p)
	}
	ports = append(ports, 8787, 8888)
	slices.Sort(ports)

	got := DeepPorts(ports)

	assert.Len(t, MaxDeepPorts, got)
	for _, p := range []int{2223, 8787, 8888, 15432} {
		assert.True(t, slices.Contains(got, p), "service port %d dropped", p)
	}
	assert.True(t, slices.IsSorted(got))
	short := []int{1, 2, 3}
	assert.Equal(t, short, DeepPorts(short))
}

func TestDeepServiceArgs(t *testing.T) {
	got := DeepServiceArgs([]netip.Addr{must.Value(netip.ParseAddr("10.20.0.7"))}, []int{15432}, Opts{MaxRate: 10})

	want := "-sT -Pn -n -p 15432 -sV --version-intensity 4 --open --max-rate 10 -oX - 10.20.0.7"
	assert.Equal(t, want, strings.Join(got, " "))
}
