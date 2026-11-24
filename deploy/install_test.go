//go:build unix

package deploy

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/ctx42/testing/pkg/assert"
	"github.com/ctx42/testing/pkg/must"
)

// fakeDocker answers the docker commands install.sh runs and logs them.
const fakeDocker = `#!/bin/sh
echo "$*" >> "$FAKE_DOCKER_LOG"
case "$*" in
info) exit 0 ;;
"compose version --short") echo "$FAKE_COMPOSE_VERSION" ;;
"compose ps -q app") echo cid ;;
inspect*) echo healthy ;;
"compose logs --no-log-prefix app") printf '  LOGIN      ROLE       PASSWORD\n  admin      Admin      pw\n' ;;
esac
`

type installRun struct {
	code   int
	out    string
	dir    string
	docker string // logged docker commands
}

type installer struct {
	t       *testing.T
	bin     string
	log     string
	version string
}

func newInstaller(t *testing.T) *installer {
	bin := t.TempDir()
	must.Nil(os.WriteFile(filepath.Join(bin, "docker"), []byte(fakeDocker), 0o755))
	return &installer{t: t, bin: bin, log: filepath.Join(t.TempDir(), "docker.log"), version: "2.29.1"}
}

// run runs install.sh with args in a new session (no controlling
// terminal, so the scope prompt cannot block) and the compose files of
// this checkout.
func (in *installer) run(dir string, args ...string) installRun {
	in.t.Helper()
	_ = os.Remove(in.log)
	cmd := exec.Command("sh", append([]string{"../install.sh", "--dir", dir}, args...)...)
	cmd.Env = []string{"PATH=" + in.bin + ":/usr/bin:/bin", "FAKE_DOCKER_LOG=" + in.log,
		"FAKE_COMPOSE_VERSION=" + in.version, "RAMPART_INSTALL_SOURCE=.."}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else {
		must.Nil(err)
	}
	logged, _ := os.ReadFile(in.log)
	return installRun{code: code, out: out.String(), dir: dir, docker: string(logged)}
}

func readEnv(t *testing.T, dir string) (string, os.FileMode) {
	t.Helper()
	path := filepath.Join(dir, ".env")
	fi := must.Value(os.Stat(path))
	return string(must.Value(os.ReadFile(path))), fi.Mode().Perm()
}

func envValue(env, key string) string {
	for _, l := range strings.Split(env, "\n") {
		if v, ok := strings.CutPrefix(l, key+"="); ok {
			return v
		}
	}
	return ""
}

func TestInstallWritesPrivateEnvAndKeepsItOnRerun(t *testing.T) {
	in := newInstaller(t)
	dir := filepath.Join(t.TempDir(), "re")

	first := in.run(dir, "--scope", "10.0.0.0/24")

	assert.Equal(t, 0, first.code, first.out)
	env, mode := readEnv(t, dir)
	assert.Equal(t, os.FileMode(0o600), mode)
	assert.Equal(t, "10.0.0.0/24", envValue(env, "RAMPART_ALLOWED_CIDRS"))
	assert.Equal(t, "compose.yml", envValue(env, "COMPOSE_FILE"))
	assert.Len(t, 48, envValue(env, "RAMPART_DB_PASSWORD"))
	assert.Contain(t, "compose up -d", first.docker)
	assert.Contain(t, `docker compose logs app | grep "shown once"`, first.out)
	_, err := os.Stat(filepath.Join(dir, "compose.demo.yml"))
	assert.ErrorIs(t, os.ErrNotExist, err)

	second := in.run(dir, "--scope", "10.1.0.0/24,fd00::/8")

	assert.Equal(t, 0, second.code, second.out)
	env2, mode2 := readEnv(t, dir)
	assert.Equal(t, os.FileMode(0o600), mode2)
	assert.Equal(t, "10.1.0.0/24,fd00::/8", envValue(env2, "RAMPART_ALLOWED_CIDRS"))
	assert.Equal(t, envValue(env, "RAMPART_DB_PASSWORD"), envValue(env2, "RAMPART_DB_PASSWORD"))
}

func TestInstallDemo(t *testing.T) {
	in := newInstaller(t)
	dir := filepath.Join(t.TempDir(), "demo")

	r := in.run(dir, "--demo")

	assert.Equal(t, 0, r.code, r.out)
	env, _ := readEnv(t, dir)
	assert.Equal(t, "compose.yml:compose.demo.yml", envValue(env, "COMPOSE_FILE"))
	assert.Equal(t, "", envValue(env, "RAMPART_ALLOWED_CIDRS"))
	assert.Contain(t, "LOGIN      ROLE       PASSWORD", r.out)
	assert.NotContain(t, "shown once", r.out)
	_, err := os.Stat(filepath.Join(dir, "compose.demo.yml"))
	assert.NoError(t, err)
}

func TestInstallRefusesModeSwitch(t *testing.T) {
	in := newInstaller(t)
	demo := filepath.Join(t.TempDir(), "demo")
	real := filepath.Join(t.TempDir(), "real")
	assert.Equal(t, 0, in.run(demo, "--demo").code)
	assert.Equal(t, 0, in.run(real, "--scope", "10.0.0.0/24").code)

	toReal := in.run(demo, "--scope", "10.0.0.0/24")
	toDemo := in.run(real, "--demo")

	assert.Equal(t, 1, toReal.code)
	assert.Contain(t, "holds a demo install", toReal.out)
	assert.Equal(t, 1, toDemo.code)
	assert.Contain(t, "holds a regular install", toDemo.out)
	assert.NotContain(t, "compose up", toReal.docker+toDemo.docker)
}

func TestInstallRejectsBadArguments(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"scope with demo", []string{"--demo", "--scope", "10.0.0.0/24"}, "--scope and --demo"},
		{"no scope", nil, "no scan scope"},
		{"octet", []string{"--scope", "10.0.0.256/24"}, "invalid scope"},
		{"v4 prefix", []string{"--scope", "10.0.0.0/33"}, "invalid scope"},
		{"v6 prefix", []string{"--scope", "fd00::/129"}, "invalid scope"},
		{"short", []string{"--scope", "10.0.0/24"}, "invalid scope"},
		{"shell", []string{"--scope", "10.0.0.0/24;id"}, "invalid scope"},
		{"empty item", []string{"--scope", "10.0.0.0/24,"}, "invalid scope"},
		{"unknown", []string{"--bogus"}, "unknown argument"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			in := newInstaller(t)
			dir := filepath.Join(t.TempDir(), "x")

			r := in.run(dir, tc.args...)

			assert.Equal(t, 1, r.code, r.out)
			assert.Contain(t, tc.want, r.out)
			_, err := os.Stat(dir)
			assert.ErrorIs(t, os.ErrNotExist, err)
		})
	}
}

func TestInstallComposeVersionFailsClosed(t *testing.T) {
	tests := []struct {
		version string
		ok      bool
	}{
		{"2.24.0", true},
		{"v2.29.1", true},
		{"5.5.0", true},
		{"2.23.9", false},
		{"1.29.2", false},
		{"", false},
		{"dev", false},
		{"2.x", false},
	}
	for _, tc := range tests {
		t.Run(tc.version, func(t *testing.T) {
			in := newInstaller(t)
			in.version = tc.version

			r := in.run(filepath.Join(t.TempDir(), "x"), "--scope", "10.0.0.0/24")

			assert.Equal(t, tc.ok, r.code == 0, r.out)
		})
	}
}

func TestInstallScopeUpdateNeedsScopeLine(t *testing.T) {
	in := newInstaller(t)
	dir := filepath.Join(t.TempDir(), "x")
	must.Nil(os.MkdirAll(dir, 0o700))
	must.Nil(os.WriteFile(filepath.Join(dir, ".env"), []byte("COMPOSE_FILE=compose.yml\nRAMPART_DB_PASSWORD=x\n"), 0o600))

	r := in.run(dir, "--scope", "10.0.0.0/24")

	assert.Equal(t, 1, r.code, r.out)
	assert.Contain(t, "RAMPART_ALLOWED_CIDRS", r.out)
}
