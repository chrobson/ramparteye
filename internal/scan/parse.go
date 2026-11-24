package scan

import (
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/chrobson/ramparteye/internal/model"
)

const (
	// MaxOutputBytes caps how much nmap output is read and parsed.
	MaxOutputBytes = 64 << 20
	// MaxFieldBytes caps every text field taken from a scanned host.
	MaxFieldBytes = 512
)

// maxOutput is the effective cap; a variable only so tests can lower it.
var maxOutput int64 = MaxOutputBytes

// ErrOutputTooLarge is returned when nmap output exceeds MaxOutputBytes.
var ErrOutputTooLarge = errors.New("nmap output exceeds the size limit")

// Result is the parsed content of one nmap XML report (-oX). It is built in
// memory only: the raw XML is never written to disk.
type Result struct {
	Hosts    []model.HostObs    // every <host> element, up or down
	Services []model.ServiceObs // open ports only (state "open")
	Stats    Stats              // run statistics for the safety receipt
	Runs     []Run              // one entry per nmap invocation (set by Nmap)
}

// Run records one nmap invocation for the safety receipt.
type Run struct {
	Argv    []string       // the command line actually executed
	Targets []netip.Prefix // vetted target operands
	Packets int64          // sent packets (counter or estimate)
	Raw     bool           // Packets came from nmap's own counter
	Elapsed time.Duration
	Start   time.Time
	End     time.Time
}

// Stats are the run-level numbers of one nmap report.
type Stats struct {
	Elapsed     float64 // <runstats><finished elapsed>, seconds
	HostsTotal  int     // <runstats><hosts total>
	ScanType    string  // <scaninfo type>, e.g. "syn", "connect"; "" for -sn
	NumServices int     // <scaninfo numservices>: ports per host
}

// UpHosts returns the addresses of hosts reported up, sorted.
func (r Result) UpHosts() []netip.Addr {
	var out []netip.Addr
	for _, h := range r.Hosts {
		if h.Up {
			out = append(out, h.IP)
		}
	}
	sortAddrs(out)
	return out
}

// nmapRun mirrors the subset of the nmap XML schema we need.
type nmapRun struct {
	XMLName  xml.Name `xml:"nmaprun"`
	ScanInfo []struct {
		Type        string `xml:"type,attr"`
		NumServices int    `xml:"numservices,attr"`
	} `xml:"scaninfo"`
	Hosts    []xmlHost  `xml:"host"`
	RunStats xmlRunStat `xml:"runstats"`
}

type xmlRunStat struct {
	Finished struct {
		Exit    string  `xml:"exit,attr"`
		ErrMsg  string  `xml:"errormsg,attr"`
		Elapsed float64 `xml:"elapsed,attr"`
	} `xml:"finished"`
	Hosts struct {
		Total int `xml:"total,attr"`
	} `xml:"hosts"`
}

type xmlHost struct {
	Status struct {
		State string `xml:"state,attr"`
	} `xml:"status"`
	Addresses []struct {
		Addr     string `xml:"addr,attr"`
		AddrType string `xml:"addrtype,attr"`
	} `xml:"address"`
	Hostnames []struct {
		Name string `xml:"name,attr"`
		Type string `xml:"type,attr"`
	} `xml:"hostnames>hostname"`
	Ports []xmlPort `xml:"ports>port"`
}

type xmlPort struct {
	Protocol string `xml:"protocol,attr"`
	PortID   int    `xml:"portid,attr"`
	State    struct {
		State string `xml:"state,attr"`
	} `xml:"state"`
	Service *struct {
		Name      string   `xml:"name,attr"`
		Product   string   `xml:"product,attr"`
		Version   string   `xml:"version,attr"`
		ExtraInfo string   `xml:"extrainfo,attr"`
		Tunnel    string   `xml:"tunnel,attr"`
		CPE       []string `xml:"cpe"`
	} `xml:"service"`
}

// Parse decodes an nmap XML report. It is a pure function (no I/O besides
// reading r) so it can be tested on recorded fixtures. Only IPv4/IPv6
// addresses are used; MAC addresses are ignored. Services are only taken from
// ports in state "open" and are keyed by model.AssetKey with an empty VHost.
//
// Banner is the nmap service name, prefixed with "ssl/" when nmap detected a
// TLS tunnel (e.g. "ssl/http"), which lets the HTTP prober pick the scheme.
//
// At most MaxOutputBytes are read and text taken from scanned hosts is
// clipped to MaxFieldBytes, so hostile hosts cannot blow up memory.
func Parse(r io.Reader) (Result, error) {
	var run nmapRun
	lr := &io.LimitedReader{R: r, N: maxOutput + 1}
	dec := xml.NewDecoder(lr)
	// nmap XML is UTF-8 but older versions may declare other charsets.
	dec.CharsetReader = func(_ string, in io.Reader) (io.Reader, error) { return in, nil }
	if err := dec.Decode(&run); err != nil {
		if lr.N <= 0 {
			return Result{}, ErrOutputTooLarge
		}
		return Result{}, fmt.Errorf("parse nmap xml: %w", err)
	}
	if run.RunStats.Finished.Exit == "error" {
		return Result{}, fmt.Errorf("nmap reported error: %s", run.RunStats.Finished.ErrMsg)
	}
	var res Result
	res.Stats.Elapsed = run.RunStats.Finished.Elapsed
	res.Stats.HostsTotal = run.RunStats.Hosts.Total
	for _, si := range run.ScanInfo {
		if res.Stats.ScanType == "" {
			res.Stats.ScanType = si.Type
		}
		res.Stats.NumServices += si.NumServices
	}
	seenHost := map[netip.Addr]int{}
	seenSvc := map[model.AssetKey]bool{}
	for _, h := range run.Hosts {
		ip, ok := hostAddr(h)
		if !ok {
			continue
		}
		obs := model.HostObs{IP: ip, Up: h.Status.State == "up", Hostname: clip(hostName(h), MaxFieldBytes)}
		if i, dup := seenHost[ip]; dup {
			// The same host can appear twice (e.g. retried); "up" wins.
			res.Hosts[i].Up = res.Hosts[i].Up || obs.Up
			if res.Hosts[i].Hostname == "" {
				res.Hosts[i].Hostname = obs.Hostname
			}
		} else {
			seenHost[ip] = len(res.Hosts)
			res.Hosts = append(res.Hosts, obs)
		}
		for _, p := range h.Ports {
			if p.State.State != "open" || p.PortID <= 0 || p.PortID > 65535 {
				continue
			}
			key := model.AssetKey{IP: ip, Port: uint16(p.PortID), Proto: strings.ToLower(p.Protocol)}
			if seenSvc[key] {
				continue
			}
			seenSvc[key] = true
			svc := model.ServiceObs{Key: key}
			if s := p.Service; s != nil {
				svc.Product = clip(strings.TrimSpace(s.Product), MaxFieldBytes)
				svc.Version = clip(strings.TrimSpace(s.Version), MaxFieldBytes)
				svc.ExtraInfo = clip(strings.TrimSpace(s.ExtraInfo), MaxFieldBytes)
				if len(s.CPE) > 0 {
					svc.CPE = clip(strings.TrimSpace(s.CPE[0]), MaxFieldBytes)
				}
				svc.Banner = clip(s.Name, MaxFieldBytes)
				if s.Tunnel != "" && s.Name != "" {
					svc.Banner = clip(s.Tunnel+"/"+s.Name, MaxFieldBytes)
				}
			}
			res.Services = append(res.Services, svc)
		}
	}
	sort.Slice(res.Hosts, func(i, j int) bool { return res.Hosts[i].IP.Less(res.Hosts[j].IP) })
	sort.Slice(res.Services, func(i, j int) bool { return keyLess(res.Services[i].Key, res.Services[j].Key) })
	return res, nil
}

func hostAddr(h xmlHost) (netip.Addr, bool) {
	for _, a := range h.Addresses {
		if a.AddrType != "ipv4" && a.AddrType != "ipv6" {
			continue
		}
		ip, err := netip.ParseAddr(a.Addr)
		if err != nil {
			continue
		}
		return ip.Unmap(), true
	}
	return netip.Addr{}, false
}

// hostName prefers the user-supplied name, then the PTR record.
func hostName(h xmlHost) string {
	var ptr string
	for _, n := range h.Hostnames {
		switch n.Type {
		case "user":
			return n.Name
		case "PTR":
			if ptr == "" {
				ptr = n.Name
			}
		default:
			if ptr == "" {
				ptr = n.Name
			}
		}
	}
	return ptr
}

func keyLess(a, b model.AssetKey) bool {
	if a.IP != b.IP {
		return a.IP.Less(b.IP)
	}
	if a.Port != b.Port {
		return a.Port < b.Port
	}
	if a.Proto != b.Proto {
		return a.Proto < b.Proto
	}
	return a.VHost < b.VHost
}

func sortAddrs(a []netip.Addr) {
	sort.Slice(a, func(i, j int) bool { return a[i].Less(a[j]) })
}

// clip returns s as valid UTF-8 cut to at most n bytes on a rune boundary.
func clip(s string, n int) string {
	s = strings.ToValidUTF8(s, "")
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}
