package runner

import (
	"fmt"
	"slices"

	"github.com/chrobson/ramparteye/internal/config"
	"github.com/chrobson/ramparteye/internal/store"
)

// Port profiles of a scan profile (scan_configs.port_profile).
const (
	ProfileAuto = "auto" // all ports for small targets (AllPortsMaxAddrs), else top
	ProfileTop  = "top"  // --top-ports N plus the extra pass
	ProfileList = "list" // explicit list (-p)
	ProfileAll  = "all"  // every TCP port (-p-)
)

// AllPorts is every TCP port, 1-65535.
var AllPorts = func() []int {
	out := make([]int, 65535)
	for i := range out {
		out[i] = i + 1
	}
	return out
}()

// PortPlan is the phase 2 port selection of a run.
type PortPlan struct {
	Profile string // effective profile: top, list or all (never auto)
	Ports   []int  // explicit -p list; nil = --top-ports
	Extra   []int  // second pass after --top-ports (top only)
}

// ProfileOf returns the port profile of cfg; an empty one is list when the
// profile has a port list, else auto.
func ProfileOf(cfg store.ScanConfig) string {
	switch {
	case cfg.PortProfile != "":
		return cfg.PortProfile
	case cfg.Ports != "":
		return ProfileList
	default:
		return ProfileAuto
	}
}

// ResolvePorts picks the phase 2 ports for addrs addresses of cfg. The auto
// profile scans every port when 0 < addrs <= allPortsMax (16 by default),
// else the top ports. allowed is RAMPART_SCAN_PORTS (nil = no restriction)
// and defaultExtra the built-in extra pass (scan.DefaultExtraPorts). A scan
// never widens past allowed: with a restriction, top and all scan exactly
// the allowed ports.
func ResolvePorts(cfg store.ScanConfig, addrs uint64, allPortsMax int, allowed, defaultExtra []int) (PortPlan, error) {
	profile := ProfileOf(cfg)
	if profile == ProfileAuto {
		profile = ProfileTop
		if allPortsMax > 0 && addrs > 0 && addrs <= uint64(allPortsMax) {
			profile = ProfileAll
		}
	}
	switch profile {
	case ProfileList:
		ports, err := EffectivePorts(cfg.Ports, allowed)
		if err != nil {
			return PortPlan{}, err
		}
		if len(ports) == 0 {
			return PortPlan{}, fmt.Errorf("port profile %q needs a port list", ProfileList)
		}
		return PortPlan{Profile: profile, Ports: ports}, nil
	case ProfileAll:
		if len(allowed) > 0 {
			return PortPlan{Profile: profile, Ports: allowed}, nil
		}
		return PortPlan{Profile: profile, Ports: AllPorts}, nil
	case ProfileTop:
		if len(allowed) > 0 {
			return PortPlan{Profile: profile, Ports: allowed}, nil
		}
		own, err := config.ParsePorts(cfg.ExtraPortList)
		if err != nil {
			return PortPlan{}, fmt.Errorf("extra ports: %w", err)
		}
		var extra []int
		if cfg.ExtraPorts {
			extra = append(extra, defaultExtra...)
		}
		extra = append(extra, own...)
		slices.Sort(extra)
		return PortPlan{Profile: profile, Extra: slices.Compact(extra)}, nil
	default:
		return PortPlan{}, fmt.Errorf("unknown port profile %q", profile)
	}
}

// EffectivePorts returns the explicit port list of a profile: its own list
// (spec) intersected with allowed, or allowed when spec is empty; nil means
// --top-ports. A spec with no port left after the intersection is an error,
// so a scan never silently widens to the top ports.
func EffectivePorts(spec string, allowed []int) ([]int, error) {
	own, err := config.ParsePorts(spec)
	if err != nil {
		return nil, err
	}
	if len(allowed) == 0 {
		return own, nil
	}
	if len(own) == 0 {
		return allowed, nil
	}
	var out []int
	for _, p := range own {
		if slices.Contains(allowed, p) {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("none of the ports %q is allowed (RAMPART_SCAN_PORTS)", spec)
	}
	return out, nil
}
