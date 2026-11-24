package runner

import (
	"fmt"
	"testing"

	"github.com/ctx42/testing/pkg/assert"

	"github.com/chrobson/ramparteye/internal/store"
)

func TestEffectivePorts(t *testing.T) {
	cases := []struct {
		spec    string
		allowed []int
		want    []int
		err     bool
	}{
		{"", nil, nil, false},
		{"22,80", nil, []int{22, 80}, false},
		{"", []int{22, 443}, []int{22, 443}, false},
		{"22,80,443", []int{22, 443}, []int{22, 443}, false},
		{"80", []int{22, 443}, nil, true}, // never widened to top ports
		{"x", nil, nil, true},
	}
	for _, c := range cases {
		t.Run(c.spec, func(t *testing.T) {
			got, err := EffectivePorts(c.spec, c.allowed)
			if c.err {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, c.want, got)
		})
	}
}

func TestResolvePorts(t *testing.T) {
	extra := []int{1883, 6379}
	cases := []struct {
		name    string
		cfg     store.ScanConfig
		addrs   uint64
		allowed []int
		want    string // profile ports(count or list) extra
		err     bool
	}{
		{"auto single -> all", store.ScanConfig{}, 1, nil, "all 65535 []", false},
		{"auto 16 -> all", store.ScanConfig{PortProfile: "auto"}, 16, nil, "all 65535 []", false},
		{"auto 17 -> top", store.ScanConfig{PortProfile: "auto", ExtraPorts: true}, 17, nil, "top 0 [1883 6379]", false},
		{"auto unknown size -> top", store.ScanConfig{}, 0, nil, "top 0 []", false},
		{"legacy list", store.ScanConfig{Ports: "22,80"}, 1, nil, "list [22 80] []", false},
		{"top + own extra", store.ScanConfig{PortProfile: "top", ExtraPorts: true, ExtraPortList: "8787,6379,15432"}, 1, nil,
			"top 0 [1883 6379 8787 15432]", false},
		{"top own extra only", store.ScanConfig{PortProfile: "top", ExtraPortList: "8787"}, 1, nil, "top 0 [8787]", false},
		{"top restricted", store.ScanConfig{PortProfile: "top", ExtraPorts: true}, 1, []int{22, 80}, "top [22 80] []", false},
		{"all restricted", store.ScanConfig{PortProfile: "all"}, 1000, []int{22}, "all [22] []", false},
		{"all big", store.ScanConfig{PortProfile: "all"}, 1 << 20, nil, "all 65535 []", false},
		{"list needs ports", store.ScanConfig{PortProfile: "list"}, 1, nil, "", true},
		{"bad extra", store.ScanConfig{PortProfile: "top", ExtraPortList: "x"}, 1, nil, "", true},
		{"bad profile", store.ScanConfig{PortProfile: "nope"}, 1, nil, "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			pp, err := ResolvePorts(c.cfg, c.addrs, 16, c.allowed, extra)
			if c.err {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			ports := fmt.Sprint(pp.Ports)
			if len(pp.Ports) > 10 || len(pp.Ports) == 0 {
				ports = fmt.Sprint(len(pp.Ports))
			}
			assert.Equal(t, c.want, fmt.Sprintf("%s %s %v", pp.Profile, ports, pp.Extra))
		})
	}
}
