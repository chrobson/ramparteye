// Package deploy holds the deployment files; its tests check that the
// compose files stay consistent with the database init script and the lab
// ground truth.
package deploy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/ctx42/testing/pkg/assert"
	"github.com/ctx42/testing/pkg/must"
	"go.yaml.in/yaml/v3"
)

type composeFile struct {
	Services map[string]service `yaml:"services"`
	Volumes  map[string]any     `yaml:"volumes"`
	Configs  map[string]struct {
		Content string `yaml:"content"`
	} `yaml:"configs"`
	Networks map[string]struct {
		Name string `yaml:"name"`
		IPAM struct {
			Config []struct {
				Subnet string `yaml:"subnet"`
			} `yaml:"config"`
		} `yaml:"ipam"`
	} `yaml:"networks"`
}

type service struct {
	Image           string            `yaml:"image"`
	User            string            `yaml:"user"`
	NetworkMode     yaml.Node         `yaml:"network_mode"`
	StopGracePeriod string            `yaml:"stop_grace_period"`
	ReadOnly        bool              `yaml:"read_only"`
	Volumes         []string          `yaml:"volumes"`
	Environment     map[string]string `yaml:"environment"`
	CapAdd          []string          `yaml:"cap_add"`
	Networks        map[string]struct {
		IPv4 string `yaml:"ipv4_address"`
	} `yaml:"networks"`
	Configs []struct {
		Source string `yaml:"source"`
		Target string `yaml:"target"`
	} `yaml:"configs"`
}

func loadCompose(t *testing.T, path string) composeFile {
	t.Helper()
	var c composeFile
	must.Nil(yaml.Unmarshal(must.Value(os.ReadFile(filepath.FromSlash(path))), &c))
	return c
}

// labIPs returns the lab address of every service in the compose files
// (later files override earlier ones; scale 0 is not modelled, the
// variants only add services).
func labIPs(cs ...composeFile) map[string]string {
	ips := map[string]string{}
	for _, c := range cs {
		for name, s := range c.Services {
			if n, ok := s.Networks["lab"]; ok && n.IPv4 != "" {
				ips[n.IPv4] = name
			}
		}
	}
	return ips
}

type expectedRun struct {
	Network string `json:"network"`
	Infra   []struct {
		IP string `json:"ip"`
	} `json:"infra"`
	Hosts []struct {
		IP   string `json:"ip"`
		Name string `json:"name"`
	} `json:"hosts"`
}

func loadExpected(t *testing.T, run string) expectedRun {
	t.Helper()
	var e expectedRun
	must.Nil(json.Unmarshal(must.Value(os.ReadFile(filepath.Join("..", "lab", "expected", run+".json"))), &e))
	return e
}

func TestComposeDatabaseInitMatchesScript(t *testing.T) {
	c := loadCompose(t, "../compose.yml")
	want := string(must.Value(os.ReadFile(filepath.Join("db", "init", "01-tde.sql"))))

	cfg, ok := c.Configs["tde-init"]

	assert.True(t, ok)
	assert.Equal(t, want, cfg.Content)
	db := c.Services["db"]
	assert.True(t, slices.ContainsFunc(db.Configs, func(x struct {
		Source string `yaml:"source"`
		Target string `yaml:"target"`
	}) bool {
		return x.Source == "tde-init" && x.Target == "/docker-entrypoint-initdb.d/01-tde.sql"
	}))
}

func TestComposeVolumesAreSeparate(t *testing.T) {
	c := loadCompose(t, "../compose.yml")

	app, db := c.Services["app"], c.Services["db"]

	assert.Equal(t, []string{"secrets:/var/lib/ramparteye/secrets"}, app.Volumes)
	assert.Equal(t, []string{"pgdata:/data/db", "pgkeys:/keys"}, db.Volumes)
	assert.Len(t, 3, c.Volumes)
}

func TestComposeApp(t *testing.T) {
	c := loadCompose(t, "../compose.yml")

	app := c.Services["app"]

	assert.Equal(t, "host", app.NetworkMode.Value)
	assert.Equal(t, "30s", app.StopGracePeriod)
	assert.True(t, app.ReadOnly)
	assert.Equal(t, "${RAMPART_IMAGE:-ghcr.io/chrobson/ramparteye:latest}", app.Image)
	assert.Equal(t, "/var/lib/ramparteye/secrets", app.Environment["RAMPART_SECRETS_DIR"])
}

func TestComposeDemoApp(t *testing.T) {
	c := loadCompose(t, "../compose.demo.yml")

	app := c.Services["app"]

	assert.Equal(t, "!reset", app.NetworkMode.Tag)
	assert.Equal(t, "1", app.Environment["RAMPART_DEMO"])
	assert.Equal(t, "10.20.0.0/18", app.Environment["RAMPART_ALLOWED_CIDRS"])
	assert.Equal(t, "true", app.Environment["RAMPART_SCAN_PRIVILEGED"])
	assert.Equal(t, []string{"NET_RAW", "NET_ADMIN"}, app.CapAdd)
	assert.Equal(t, "10.20.63.251", app.Networks["lab"].IPv4)
	assert.Equal(t, "ramparteye-lab", c.Networks["lab"].Name)
	assert.Equal(t, "10.20.0.0/18", c.Networks["lab"].IPAM.Config[0].Subnet)
}

func TestDemoLabMatchesExpected(t *testing.T) {
	demo := loadCompose(t, "../compose.demo.yml")
	tests := []struct {
		run      string
		variants []string
	}{
		{"run1", nil},
		{"run2", []string{"run2"}},
		{"run3", []string{"run3"}},
	}
	for _, tc := range tests {
		t.Run(tc.run, func(t *testing.T) {
			files := []composeFile{demo}
			for _, v := range tc.variants {
				files = append(files, loadCompose(t, "../lab/variants/"+v+".yml"))
			}
			ips := labIPs(files...)
			exp := loadExpected(t, tc.run)

			assert.Equal(t, "10.20.0.0/18", exp.Network)
			for _, h := range exp.Hosts {
				assert.Equal(t, h.Name, ips[h.IP], "host %s", h.IP)
			}
			for _, i := range exp.Infra {
				if name, ok := ips[i.IP]; ok {
					assert.Equal(t, "app", name, "infra %s", i.IP)
				}
			}
		})
	}
}

// TestDemoLabConfigsExist checks that every config a lab service mounts is
// defined inline.
func TestDemoLabConfigsExist(t *testing.T) {
	demo := loadCompose(t, "../compose.demo.yml")
	files := []composeFile{demo,
		loadCompose(t, "../lab/variants/run2.yml"), loadCompose(t, "../lab/variants/run3.yml")}

	for _, f := range files {
		for name, s := range f.Services {
			for _, cf := range s.Configs {
				_, ok := demo.Configs[cf.Source]
				assert.True(t, ok, "service %s: config %s", name, cf.Source)
			}
		}
	}
}
