package scan

import (
	"regexp"
	"strconv"
)

// MeteredArgs is the command line actually executed: -v makes nmap print its
// "Raw packets sent" counter on stdout, so the XML goes to file descriptor 3
// instead of stdout. The builders keep "-oX -" so their output stays the
// documented command line.
func MeteredArgs(args []string) []string {
	out := make([]string, 0, len(args)+1)
	out = append(out, "-v")
	for i := 0; i < len(args); i++ {
		if args[i] == "-oX" && i+1 < len(args) && args[i+1] == "-" {
			out = append(out, "-oX", "/dev/fd/3")
			i++
			continue
		}
		out = append(out, args[i])
	}
	return out
}

// discoveryProbes is the number of probes phase 1 sends per address
// (-PE, -PS list, -PA list).
func discoveryProbes() int64 {
	return int64(1 + len(DiscoveryPorts) + len(DiscoveryACKPorts))
}

// EstimatePackets returns the packets one invocation sent: nmap's raw packet
// counter when it printed one, plus one SYN per probed port of a connect scan
// (connect() packets are sent by the kernel and nmap does not count them).
// Without a counter, the probes are estimated from the XML (addresses x
// ports, or addresses x discovery probes for -sn).
func EstimatePackets(st Stats, args []string, raw int64, have bool) int64 {
	hosts := int64(st.HostsTotal)
	if st.ScanType == "connect" {
		return raw + hosts*int64(st.NumServices)
	}
	if have {
		return raw
	}
	if st.NumServices > 0 {
		return hosts * int64(st.NumServices)
	}
	for _, a := range args {
		if a == "-sn" {
			return hosts * discoveryProbes()
		}
	}
	return 0
}

var rawPacketsRe = regexp.MustCompile(`Raw packets sent: (\d+)`)

// ParseRawPackets finds nmap's "Raw packets sent: N (...) | Rcvd: ..." line
// (printed under -v when raw packets were used).
func ParseRawPackets(stdout string) (int64, bool) {
	m := rawPacketsRe.FindAllStringSubmatch(stdout, -1)
	if len(m) == 0 {
		return 0, false
	}
	n, err := strconv.ParseInt(m[len(m)-1][1], 10, 64)
	return n, err == nil
}
