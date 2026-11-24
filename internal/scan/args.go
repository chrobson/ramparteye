// Package scan runs host discovery and service detection with nmap. Every
// nmap invocation is vetted against the scan scope immediately before exec.
package scan

import (
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/chrobson/ramparteye/internal/config"
)

// DiscoveryPorts are the TCP SYN ping ports used in phase 1 (-PS).
var DiscoveryPorts = []int{21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 1883, 3306, 3389, 5432, 8080, 8443}

// DiscoveryACKPorts are the TCP ACK ping ports used in phase 1 (-PA).
var DiscoveryACKPorts = []int{80, 443}

// DefaultTopPorts is used when Opts.TopPorts is not set.
const DefaultTopPorts = 1000

// DeepIntensity is the nmap --version-intensity of the DeepUnknown pass: the
// lowest level that sends the probes naming PostgreSQL, MySQL and similar
// services on non-standard ports.
const DeepIntensity = 4

// MaxDeepPorts caps the ports of one DeepUnknown pass (see DeepPorts).
const MaxDeepPorts = 32

// DefaultExtraPorts are TCP ports outside nmap's top 1000 that commonly host
// exposed infrastructure services.
var DefaultExtraPorts = []int{1883, 2375, 2376, 4222, 5601, 5672, 6222, 6379, 8086, 8161, 8883,
	9042, 9093, 9200, 9300, 10250, 11211, 15672, 27017, 33060, 50070, 61616}

// Opts controls one scanner invocation.
type Opts struct {
	TopPorts   int  // phase 2 --top-ports
	MaxRate    int  // packets/s for THIS invocation (caller splits R/K)
	Privileged bool // -sS when true, -sT -Pn otherwise
	// ExtraPorts are scanned in a second phase-2 pass on the same live hosts
	// (nmap cannot combine --top-ports with an explicit -p list).
	ExtraPorts []int
	// Ports, when set, is the explicit TCP port list of phase 2: it replaces
	// --top-ports and disables the ExtraPorts pass.
	Ports []int
	// DeepUnknown adds a pass with --version-intensity DeepIntensity over the
	// open ports the light pass could not name (at most MaxDeepPorts per
	// address family). Meant for small targets.
	DeepUnknown bool
}

// DiscoveryArgs builds the phase 1 command line (without the binary).
func DiscoveryArgs(prefixes []netip.Prefix, o Opts, exclude []netip.Addr) []string {
	args := []string{
		"-sn", "-n", "-PE",
		"-PS" + portList(DiscoveryPorts),
		"-PA" + portList(DiscoveryACKPorts),
	}
	args = appendRate(args, o.MaxRate)
	if len(exclude) > 0 {
		ex := make([]string, len(exclude))
		for i, a := range exclude {
			ex[i] = a.Unmap().String()
		}
		args = append(args, "--exclude", strings.Join(ex, ","))
	}
	if len(prefixes) > 0 && prefixes[0].Addr().Unmap().Is6() {
		args = append(args, "-6")
	}
	args = append(args, "-oX", "-")
	for _, p := range prefixes {
		p = p.Masked()
		if p.IsSingleIP() {
			args = append(args, p.Addr().String())
		} else {
			args = append(args, p.String())
		}
	}
	return args
}

// ServiceArgs builds the phase 2 command line (without the binary).
// Privileged uses a SYN scan; otherwise a connect scan. Both skip host
// discovery (-Pn) because the hosts come from phase 1.
func ServiceArgs(hosts []netip.Addr, o Opts) []string {
	top := o.TopPorts
	if top <= 0 {
		top = DefaultTopPorts
	}
	ports := []string{"--top-ports", strconv.Itoa(top)}
	if len(o.Ports) > 0 {
		ports = []string{"-p", config.FormatPorts(o.Ports)}
		if IsAllPorts(o.Ports) {
			ports = []string{"-p-"}
		}
	}
	args := []string{scanType(o), "-Pn", "-n"}
	args = append(args, ports...)
	args = append(args, "-sV", "--version-light", "--open")
	return finishHostArgs(args, hosts, o)
}

// ExtraServiceArgs builds the second phase-2 pass over o.ExtraPorts.
func ExtraServiceArgs(hosts []netip.Addr, o Opts) []string {
	args := []string{scanType(o), "-Pn", "-n", "-p", portList(o.ExtraPorts), "-sV", "--version-light", "--open"}
	return finishHostArgs(args, hosts, o)
}

// DeepServiceArgs builds the DeepUnknown pass over ports.
func DeepServiceArgs(hosts []netip.Addr, ports []int, o Opts) []string {
	args := []string{scanType(o), "-Pn", "-n", "-p", portList(ports), "-sV",
		"--version-intensity", strconv.Itoa(DeepIntensity), "--open"}
	return finishHostArgs(args, hosts, o)
}

// IsAllPorts reports whether a sorted, duplicate-free port list is every TCP
// port (1-65535), which nmap spells -p-.
func IsAllPorts(ps []int) bool {
	return len(ps) == 65535 && ps[0] == 1 && ps[len(ps)-1] == 65535
}

// DeepPorts picks at most MaxDeepPorts of the unnamed ports for the deep
// version pass. Ports that look like service ports come first; ports in the
// ephemeral range (49152+) and runs of four or more consecutive ports (for
// example FTP passive 21000-21010) are taken only while room is left. ports
// must be sorted; so is the result.
func DeepPorts(ports []int) []int {
	if len(ports) <= MaxDeepPorts {
		return ports
	}
	inRun := make([]bool, len(ports))
	for i := 0; i < len(ports); {
		j := i
		for j+1 < len(ports) && ports[j+1] == ports[j]+1 {
			j++
		}
		if j-i+1 >= 4 {
			for k := i; k <= j; k++ {
				inRun[k] = true
			}
		}
		i = j + 1
	}
	var first, rest []int
	for i, p := range ports {
		if p >= 49152 || inRun[i] {
			rest = append(rest, p)
		} else {
			first = append(first, p)
		}
	}
	out := append(first, rest...)
	out = out[:MaxDeepPorts]
	sort.Ints(out)
	return out
}

func scanType(o Opts) string {
	if o.Privileged {
		return "-sS"
	}
	return "-sT"
}

// finishHostArgs appends rate, address family, output and the host operands.
func finishHostArgs(args []string, hosts []netip.Addr, o Opts) []string {
	args = appendRate(args, o.MaxRate)
	if len(hosts) > 0 && hosts[0].Unmap().Is6() {
		args = append(args, "-6")
	}
	args = append(args, "-oX", "-")
	for _, h := range hosts {
		args = append(args, h.Unmap().String())
	}
	return args
}

func appendRate(args []string, rate int) []string {
	if rate > 0 {
		args = append(args, "--max-rate", strconv.Itoa(rate))
	}
	return args
}

// portList renders ints as a comma separated nmap port list.
func portList(ps []int) string {
	s := make([]string, len(ps))
	for i, p := range ps {
		s[i] = strconv.Itoa(p)
	}
	return strings.Join(s, ",")
}
