package scan

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/chrobson/ramparteye/internal/model"
	"github.com/ctx42/testing/pkg/assert"
	"github.com/ctx42/testing/pkg/must"
)

func parseFixture(t *testing.T, name string) Result {
	t.Helper()
	f := must.Value(os.Open(filepath.Join("testdata", name)))
	defer func() { _ = f.Close() }()
	res, err := Parse(f)
	assert.NoError(t, err)
	return res
}

func findSvc(res Result, ip string, port uint16) (model.ServiceObs, bool) {
	a := netip.MustParseAddr(ip)
	for _, s := range res.Services {
		if s.Key.IP == a && s.Key.Port == port {
			return s, true
		}
	}
	return model.ServiceObs{}, false
}

// Counts come from the <hosts up=...> summary (discovery) and the <host> and
// "open" port elements of the recorded lab scans. With --open nmap omits
// hosts without open ports from <host> elements.
func TestParseLabFixtures(t *testing.T) {
	cases := []struct {
		file     string
		up, svcs int
	}{
		{"run1_discovery.xml", 33, 0},
		{"run2_discovery.xml", 32, 0},
		{"run1_services.xml", 27, 31},
		{"run2_services.xml", 27, 31},
	}
	for _, c := range cases {
		t.Run(c.file, func(t *testing.T) {
			res := parseFixture(t, c.file)

			assert.Len(t, c.up, res.UpHosts())
			assert.Len(t, c.svcs, res.Services)
			for _, s := range res.Services {
				assert.Equal(t, "tcp", s.Key.Proto)
				assert.True(t, s.Key.Port != 0 && s.Key.IP.Is4() && s.Key.VHost == "")
			}
		})
	}
}

func TestParseLabServiceDetails(t *testing.T) {
	res := parseFixture(t, "run1_services.xml")

	s, ok := findSvc(res, "10.20.0.11", 443)
	assert.True(t, ok)
	assert.Equal(t, "nginx", s.Product)
	assert.Equal(t, "1.27.3", s.Version)
	assert.Equal(t, "ssl/http", s.Banner)
	assert.Equal(t, "cpe:/a:igor_sysoev:nginx:1.27.3", s.CPE)

	s, ok = findSvc(res, "10.20.0.10", 80)
	assert.True(t, ok)
	assert.Equal(t, "http", s.Banner)
	assert.Equal(t, "nginx", s.Product)

	for i := 1; i < len(res.Services); i++ {
		assert.False(t, keyLess(res.Services[i].Key, res.Services[i-1].Key), "unsorted at %d", i)
	}
}

func TestParseEdgeCases(t *testing.T) {
	res := parseFixture(t, "edge_services.xml")

	assert.Len(t, 3, res.Hosts)
	h := res.Hosts[0]
	assert.Equal(t, netip.MustParseAddr("192.0.2.10"), h.IP)
	assert.True(t, h.Up)
	assert.Equal(t, "www.example.test", h.Hostname)
	d := res.Hosts[1]
	assert.False(t, d.Up)
	assert.Equal(t, "down.example.test", d.Hostname)
	assert.Len(t, 2, res.UpHosts())

	// open only: not filtered 8080, not open|filtered 53.
	want := "192.0.2.10:22/tcp 192.0.2.10:161/udp 192.0.2.10:443/tcp 192.0.2.10:9999/tcp 192.0.2.12:80/tcp"
	var got []string
	for _, s := range res.Services {
		got = append(got, netip.AddrPortFrom(s.Key.IP, s.Key.Port).String()+"/"+s.Key.Proto)
	}
	assert.Equal(t, want, strings.Join(got, " "))

	ssh, _ := findSvc(res, "192.0.2.10", 22)
	assert.Equal(t, "9.6p1 Ubuntu 3ubuntu13.5", ssh.Version)
	assert.Equal(t, "Ubuntu Linux; protocol 2.0", ssh.ExtraInfo)
	assert.Equal(t, "cpe:/a:openbsd:openssh:9.6p1", ssh.CPE)
	bare, _ := findSvc(res, "192.0.2.10", 9999)
	assert.Equal(t, "", bare.Banner)
	assert.Equal(t, "", bare.Product)
}

func TestParseErrors(t *testing.T) {
	data := must.Value(os.ReadFile(filepath.Join("testdata", "run1_services.xml")))

	_, err := Parse(strings.NewReader(string(data[:len(data)/2])))
	assert.Error(t, err)

	_, err = Parse(strings.NewReader(""))
	assert.Error(t, err)

	failed := `<?xml version="1.0"?><nmaprun><runstats><finished exit="error" errormsg="Failed to open device"/></runstats></nmaprun>`
	_, err = Parse(strings.NewReader(failed))
	assert.ErrorContain(t, "Failed to open device", err)
}

var blanks = []byte(strings.Repeat(" ", 32*1024))

// endlessReader yields an unterminated XML document forever.
type endlessReader struct {
	head string
	n    int64
}

func (r *endlessReader) Read(p []byte) (int, error) {
	if r.head != "" {
		n := copy(p, r.head)
		r.head = r.head[n:]
		r.n += int64(n)
		return n, nil
	}
	n := copy(p, blanks)
	r.n += int64(n)
	return n, nil
}

func TestParseCapsOutputSize(t *testing.T) {
	maxOutput = 1 << 20
	defer func() { maxOutput = MaxOutputBytes }()
	r := &endlessReader{head: `<?xml version="1.0"?><nmaprun>`}

	_, err := Parse(r)

	assert.Error(t, err)
	assert.True(t, r.n <= maxOutput+64*1024, "read %d bytes", r.n)
}

func TestParseHostileContent(t *testing.T) {
	long := strings.Repeat("A", 100_000)
	doc := `<?xml version="1.0"?><nmaprun><host><status state="up"/>` +
		`<address addr="10.20.0.9" addrtype="ipv4"/>` +
		`<hostnames><hostname name="` + long + `" type="user"/></hostnames><ports>` +
		`<port protocol="tcp" portid="80"><state state="open"/>` +
		`<service name="http" product="&lt;script&gt;alert(1)&lt;/script&gt;` + long + `" version="` + long + `"/></port>` +
		`</ports></host></nmaprun>`

	res, err := Parse(strings.NewReader(doc))

	assert.NoError(t, err)
	assert.Len(t, 1, res.Services)
	s := res.Services[0]
	assert.True(t, len(s.Product) <= MaxFieldBytes)
	assert.True(t, len(s.Version) <= MaxFieldBytes)
	assert.True(t, len(res.Hosts[0].Hostname) <= MaxFieldBytes)
	assert.True(t, strings.HasPrefix(s.Product, "<script>"), "content is kept verbatim for later escaping")
}

func TestParseTruncatesOnRuneBoundary(t *testing.T) {
	got := clip(strings.Repeat("é", MaxFieldBytes), MaxFieldBytes)

	assert.True(t, len(got) <= MaxFieldBytes)
	assert.Equal(t, got, strings.ToValidUTF8(got, ""))
}

func TestParseMalformedDoesNotPanic(t *testing.T) {
	docs := []string{
		"\xff\xfe<nmaprun>",
		`<nmaprun><host><address addr="999.1.1.1" addrtype="ipv4"/></host></nmaprun>`,
		`<nmaprun><host><address addr="10.0.0.1" addrtype="ipv4"/><ports><port portid="-5" protocol="tcp"><state state="open"/></port></ports></host></nmaprun>`,
		`<nmaprun><host><address addr="10.0.0.1" addrtype="ipv4"/><ports><port portid="99999999999999999999"/></ports></host></nmaprun>`,
		strings.Repeat("<a>", 100_000),
		`<!DOCTYPE x [<!ENTITY a "&a;">]><nmaprun>&a;</nmaprun>`,
	}
	for _, d := range docs {
		func() {
			defer func() { assert.Nil(t, recover()) }()
			_, _ = Parse(strings.NewReader(d))
		}()
	}
}
