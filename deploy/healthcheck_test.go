package deploy

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/ctx42/testing/pkg/assert"
	"github.com/ctx42/testing/pkg/must"
	"go.yaml.in/yaml/v3"
)

type healthcheckFile struct {
	Services map[string]struct {
		Healthcheck struct {
			Test []string `yaml:"test"`
		} `yaml:"healthcheck"`
	} `yaml:"services"`
}

func healthcheckTest(t *testing.T, path, service string) string {
	t.Helper()
	var f healthcheckFile
	must.Nil(yaml.Unmarshal(must.Value(os.ReadFile(filepath.FromSlash(path))), &f))
	return strings.Join(f.Services[service].Healthcheck.Test, " ")
}

// The container is healthy when /healthz answers (process serving and
// database reachable), not merely when the login page renders.
func TestContainerHealthChecksUseHealthz(t *testing.T) {
	docker := string(must.Value(os.ReadFile("../Dockerfile")))
	hc := regexp.MustCompile(`HEALTHCHECK(?:[^\n]*\\\n)*[^\n]*`).FindString(docker)

	assert.Contain(t, "http://127.0.0.1:9080/healthz", hc)
	assert.NotContain(t, "/login", hc)

	for _, file := range []string{"../compose.yml", "../compose.demo.yml"} {
		got := healthcheckTest(t, file, "app")

		assert.Contain(t, "/healthz", got, file)
		assert.NotContain(t, "/login", got, file)
	}
}

// The e2e script waits for the app with the health endpoint, so it does not
// start while the database is still unreachable.
func TestE2EWaitsForHealthz(t *testing.T) {
	script := string(must.Value(os.ReadFile("../scripts/e2e.sh")))

	assert.Contain(t, `"$BASE/healthz"`, script)
	assert.NotContain(t, `"$BASE/login" 2>/dev/null && break`, script)
}
