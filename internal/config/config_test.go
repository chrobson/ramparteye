package config

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/ctx42/testing/pkg/assert"
	"github.com/ctx42/testing/pkg/must"
)

func envMap(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestLoadDefaults(t *testing.T) {
	cfg, err := Load(envMap(nil))

	assert.NoError(t, err)
	assert.Equal(t, ":9080", cfg.HTTPAddr)
	assert.Equal(t, 5000, cfg.MaxRate)
	assert.Equal(t, UnstableConfig{InactiveAfterMisses: 3, UnstableIfFlips: 2, Window: 5}, cfg.Unstable)
	assert.Len(t, 0, cfg.AllowedCIDRs)
	assert.Len(t, 0, cfg.ScanExclude)
	assert.Len(t, 0, cfg.ScanPorts)
	assert.Len(t, 0, cfg.AllowHosts)
	assert.Equal(t, "nmap", cfg.NmapPath)
	assert.Equal(t, time.Minute, cfg.TickEvery)
	assert.Equal(t, 16, cfg.AllPortsMaxAddrs)
	assert.Equal(t, 10*time.Second, cfg.HTTPTimeout)
	assert.Equal(t, 1, cfg.HTTPRetries)
	assert.Equal(t, "/var/lib/ramparteye/secrets", cfg.SecretsDir)
	assert.False(t, cfg.Demo)
	assert.False(t, cfg.ScanPrivileged)
	assert.Equal(t, "RampartEye", cfg.DojoProductType)
	assert.Equal(t, "Continuous discovery", cfg.DojoEngagement)
	assert.Len(t, 0, cfg.SecretKey)
}

func TestLoadNoDefaultScope(t *testing.T) {
	cfg, err := Load(envMap(nil))

	assert.NoError(t, err)
	assert.Len(t, 0, cfg.AllowedCIDRs)
}

func TestLoadValues(t *testing.T) {
	cfg, err := Load(envMap(map[string]string{
		"RAMPART_ALLOWED_CIDRS":         "10.0.0.0/24, 192.0.2.7",
		"RAMPART_SCAN_EXCLUDE":          "10.0.0.1",
		"RAMPART_SCAN_PORTS":            "22,80",
		"RAMPART_ALLOW_HOSTS":           "a.example, b.example",
		"RAMPART_MAX_RATE":              "100",
		"RAMPART_SCAN_PRIVILEGED":       "true",
		"RAMPART_DEMO":                  "1",
		"RAMPART_HTTP_RETRIES":          "0",
		"RAMPART_HTTP_TIMEOUT":          "3s",
		"RAMPART_DOJO_PRODUCT":          "Edge",
		"RAMPART_UNSTABLE_WINDOW":       "8",
		"RAMPART_UNSTABLE_IF_FLIPS":     "4",
		"RAMPART_INACTIVE_AFTER_MISSES": "6",
		"RAMPART_ALL_PORTS_MAX_ADDRS":   "0",
		"RAMPART_DOJO_PRODUCT_TYPE":     "PT",
		"RAMPART_DOJO_ENGAGEMENT":       "Eng",
		"RAMPART_SECRET_KEY":            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
	}))

	assert.NoError(t, err)
	assert.Equal(t, []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/24"), netip.MustParsePrefix("192.0.2.7/32"),
	}, cfg.AllowedCIDRs)
	assert.Equal(t, []netip.Addr{netip.MustParseAddr("10.0.0.1")}, cfg.ScanExclude)
	assert.Equal(t, []int{22, 80}, cfg.ScanPorts)
	assert.Equal(t, []string{"a.example", "b.example"}, cfg.AllowHosts)
	assert.Equal(t, 100, cfg.MaxRate)
	assert.True(t, cfg.ScanPrivileged)
	assert.True(t, cfg.Demo)
	assert.Equal(t, 0, cfg.HTTPRetries)
	assert.Equal(t, 3*time.Second, cfg.HTTPTimeout)
	assert.Equal(t, "Edge", cfg.DojoProduct)
	assert.Equal(t, UnstableConfig{InactiveAfterMisses: 6, UnstableIfFlips: 4, Window: 8}, cfg.Unstable)
	assert.Equal(t, 0, cfg.AllPortsMaxAddrs)
	assert.Equal(t, "PT", cfg.DojoProductType)
	assert.Equal(t, "Eng", cfg.DojoEngagement)
	assert.Len(t, 32, cfg.SecretKey)
	assert.Equal(t, byte(0xff), cfg.SecretKey[31])
}

func TestLoadInvalidCIDR(t *testing.T) {
	_, err := Load(envMap(map[string]string{"RAMPART_ALLOWED_CIDRS": "10.0.0.0/33"}))

	assert.ErrorContain(t, "RAMPART_ALLOWED_CIDRS", err)
}

func TestLoadInvalidValues(t *testing.T) {
	tests := map[string]string{
		"RAMPART_MAX_RATE":              "0",
		"RAMPART_SCAN_PORTS":            "70000",
		"RAMPART_SCAN_EXCLUDE":          "nope",
		"RAMPART_HTTP_RETRIES":          "4",
		"RAMPART_HTTP_TIMEOUT":          "0s",
		"RAMPART_SECRET_KEY":            "abcd",
		"RAMPART_SCAN_PRIVILEGED":       "maybe",
		"RAMPART_DEMO":                  "maybe",
		"RAMPART_TICK_EVERY":            "soon",
		"RAMPART_UNSTABLE_WINDOW":       "0",
		"RAMPART_UNSTABLE_IF_FLIPS":     "-1",
		"RAMPART_INACTIVE_AFTER_MISSES": "0",
		"RAMPART_ALL_PORTS_MAX_ADDRS":   "-1",
	}
	for key, val := range tests {
		t.Run(key, func(t *testing.T) {
			_, err := Load(envMap(map[string]string{key: val}))

			assert.ErrorContain(t, key, err)
		})
	}
}

func TestLoadKeepsAllowHostsUnresolved(t *testing.T) {
	cfg, err := Load(envMap(map[string]string{"RAMPART_ALLOW_HOSTS": "x.invalid"}))

	assert.NoError(t, err)
	assert.Equal(t, []string{"x.invalid"}, cfg.AllowHosts)
	assert.Len(t, 0, cfg.AllowedCIDRs)
}

func TestResolveAllowHosts(t *testing.T) {
	res := func(_ context.Context, h string) ([]netip.Addr, error) {
		switch h {
		case "a":
			return []netip.Addr{netip.MustParseAddr("::ffff:10.0.0.5"), netip.MustParseAddr("fe80::1%eth0")}, nil
		case "b":
			return []netip.Addr{netip.MustParseAddr("10.0.0.5")}, nil
		}
		return nil, errors.New("no such host")
	}

	got, err := ResolveAllowHosts(context.Background(), []string{"a", "b"}, res)

	assert.NoError(t, err)
	assert.Equal(t, []netip.Prefix{
		netip.MustParsePrefix("10.0.0.5/32"), netip.MustParsePrefix("fe80::1/128"),
	}, got)
}

func TestResolveAllowHostsErrors(t *testing.T) {
	t.Run("lookup error", func(t *testing.T) {
		res := func(context.Context, string) ([]netip.Addr, error) { return nil, errors.New("boom") }
		_, err := ResolveAllowHosts(context.Background(), []string{"x"}, res)
		assert.ErrorContain(t, "resolve x", err)
	})
	t.Run("no addresses", func(t *testing.T) {
		res := func(context.Context, string) ([]netip.Addr, error) { return nil, nil }
		_, err := ResolveAllowHosts(context.Background(), []string{"x"}, res)
		assert.ErrorContain(t, "no addresses", err)
	})
}

func TestParsePortsRanges(t *testing.T) {
	got, err := ParsePorts("22,80,8000-8002")

	assert.NoError(t, err)
	assert.Equal(t, []int{22, 80, 8000, 8001, 8002}, got)
}

func TestParsePortsDedupSortEmpty(t *testing.T) {
	got, err := ParsePorts("80, 22,80")
	assert.NoError(t, err)
	assert.Equal(t, []int{22, 80}, got)

	got, err = ParsePorts("")
	assert.NoError(t, err)
	assert.Len(t, 0, got)
}

func TestParsePortsInvalid(t *testing.T) {
	for _, s := range []string{"0", "65536", "x", "90-80", "1-70000"} {
		_, err := ParsePorts(s)
		assert.Error(t, err)
	}
}

func TestFormatPorts(t *testing.T) {
	assert.Equal(t, "22,80,8000-8002", FormatPorts([]int{22, 80, 8000, 8001, 8002}))
	assert.Equal(t, "", FormatPorts(nil))
}

func TestParsePrefixes(t *testing.T) {
	got, err := ParsePrefixes("10.0.0.7/24, 2001:db8::1, ")
	assert.NoError(t, err)
	assert.Equal(t, []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/24"), netip.MustParsePrefix("2001:db8::1/128"),
	}, got)

	_, err = ParsePrefixes("bogus")
	assert.Error(t, err)
}

func TestParseAddrs(t *testing.T) {
	got, err := ParseAddrs("::ffff:10.0.0.1, 10.0.0.2")
	assert.NoError(t, err)
	assert.Equal(t, []netip.Addr{netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2")}, got)

	_, err = ParseAddrs("10.0.0.256")
	assert.Error(t, err)
}

func TestLoadWindowSmallerThanFlips(t *testing.T) {
	_, err := Load(envMap(map[string]string{
		"RAMPART_UNSTABLE_WINDOW": "1", "RAMPART_UNSTABLE_IF_FLIPS": "2",
	}))

	assert.ErrorContain(t, "RAMPART_UNSTABLE_WINDOW", err)
}

func TestLoadSecretKeyErrorDoesNotLeak(t *testing.T) {
	bad := "zz" + "00112233445566778899aabbccddeeff00112233445566778899aabbccddee"
	_, err := Load(envMap(map[string]string{"RAMPART_SECRET_KEY": bad}))

	assert.ErrorContain(t, "must be 64 hex characters", err)
	assert.False(t, strings.Contains(err.Error(), "zz"))
}

func TestParseAddrsDropsZone(t *testing.T) {
	got, err := ParseAddrs("fe80::1%eth0")

	assert.NoError(t, err)
	assert.Equal(t, []netip.Addr{netip.MustParseAddr("fe80::1")}, got)
}

func TestLoadDojoFlags(t *testing.T) {
	def, err := Load(envMap(nil))
	assert.NoError(t, err)
	assert.True(t, def.DojoAutoPush)
	assert.False(t, def.DojoCloseMissing)

	cfg, err := Load(envMap(map[string]string{
		"RAMPART_DOJO_AUTO_PUSH":     "false",
		"RAMPART_DOJO_CLOSE_MISSING": "true",
	}))
	assert.NoError(t, err)
	assert.False(t, cfg.DojoAutoPush)
	assert.True(t, cfg.DojoCloseMissing)

	_, err = Load(envMap(map[string]string{"RAMPART_DOJO_AUTO_PUSH": "maybe"}))
	assert.ErrorContain(t, "RAMPART_DOJO_AUTO_PUSH", err)
}

func TestConfigRedactsSecrets(t *testing.T) {
	c := Config{DojoToken: "TOPSECRET", SecretKey: []byte("KEYSECRET"), HTTPAddr: ":1"}
	for _, out := range []string{
		fmt.Sprintf("%v", c), fmt.Sprintf("%+v", c), fmt.Sprintf("%#v", c), fmt.Sprint(&c),
		string(must.Value(json.Marshal(c))),
	} {
		for _, leak := range []string{"TOPSECRET", "KEYSECRET"} {
			assert.False(t, strings.Contains(out, leak), out)
		}
	}
	assert.True(t, strings.Contains(fmt.Sprintf("%+v", c), ":1"))
}

func TestLoadTrustedProxies(t *testing.T) {
	cfg, err := Load(envMap(map[string]string{"RAMPART_TRUSTED_PROXIES": "10.0.0.1, 172.16.0.0/12"}))

	assert.NoError(t, err)
	assert.Equal(t, []netip.Prefix{
		netip.MustParsePrefix("10.0.0.1/32"),
		netip.MustParsePrefix("172.16.0.0/12"),
	}, cfg.TrustedProxies)
}

func TestLoadTrustedProxiesDefaultNone(t *testing.T) {
	cfg, err := Load(envMap(nil))

	assert.NoError(t, err)
	assert.Len(t, 0, cfg.TrustedProxies)
}

func TestLoadInvalidTrustedProxies(t *testing.T) {
	_, err := Load(envMap(map[string]string{"RAMPART_TRUSTED_PROXIES": "nope"}))

	assert.ErrorContain(t, "RAMPART_TRUSTED_PROXIES", err)
}

func TestLoadPathProbesPerHost(t *testing.T) {
	cfg, err := Load(envMap(nil))
	assert.NoError(t, err)
	assert.Equal(t, 50, cfg.PathProbesPerHost)

	cfg, err = Load(envMap(map[string]string{"RAMPART_PATH_PROBES_PER_HOST": "0"}))
	assert.NoError(t, err)
	assert.Equal(t, 0, cfg.PathProbesPerHost)

	_, err = Load(envMap(map[string]string{"RAMPART_PATH_PROBES_PER_HOST": "-1"}))
	assert.ErrorContain(t, "RAMPART_PATH_PROBES_PER_HOST must not be negative", err)
}

// composeOnly are .env variables read by compose.yml, not by the app.
var composeOnly = map[string]bool{"RAMPART_IMAGE": true, "RAMPART_DB_PASSWORD": true, "RAMPART_BIND": true,
	"RAMPART_PORT": true, "RAMPART_DB_PORT": true, "RAMPART_TZ": true}

// The .env template written by install.sh lists exactly the variables the
// app reads (plus the compose ones), so no documented setting is dead.
func TestInstallEnvTemplateMatchesLoad(t *testing.T) {
	read := map[string]bool{}
	_, err := Load(func(k string) string { read[k] = true; return "" })
	assert.NoError(t, err)

	src := string(must.Value(os.ReadFile("../../install.sh")))
	listed := map[string]bool{}
	for _, m := range regexp.MustCompile(`(?m)^#?(RAMPART_[A-Z_]+)=`).FindAllStringSubmatch(src, -1) {
		listed[m[1]] = true
	}
	for k := range listed {
		assert.True(t, read[k] || composeOnly[k], "install.sh lists %s, which the app does not read", k)
	}
	for k := range read {
		switch k {
		case "RAMPART_DATABASE_URL", "RAMPART_HTTP_ADDR", "RAMPART_SECRETS_DIR", "RAMPART_DEMO":
			continue // set by compose
		}
		assert.True(t, listed[k], "the app reads %s, which install.sh does not list", k)
	}
	assert.False(t, read["RAMPART_DOJO_USER"])
	assert.False(t, read["RAMPART_DOJO_PASSWORD"])
}
