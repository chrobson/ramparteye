package main

import (
	"bytes"
	"context"
	"testing"

	"github.com/ctx42/testing/pkg/assert"
)

// testEnv returns an env with captured output and the given environment
// variables; everything else is unset.
func testEnv(vars map[string]string) (*env, *bytes.Buffer, *bytes.Buffer) {
	var out, errb bytes.Buffer
	e := &env{ctx: context.Background(), stdout: &out, stderr: &errb,
		getenv: func(k string) string { return vars[k] }}
	return e, &out, &errb
}

func TestRunUnknownCommand(t *testing.T) {
	var out, errb bytes.Buffer

	code := run([]string{"ramparteye", "nope"}, &out, &errb)

	assert.Equal(t, 2, code)
	assert.Contain(t, "unknown command \"nope\"", errb.String())
}

func TestRunVersion(t *testing.T) {
	var out, errb bytes.Buffer

	code := run([]string{"ramparteye", "version"}, &out, &errb)

	assert.Equal(t, 0, code)
	assert.Equal(t, "ramparteye "+version+"\n", out.String())
}

func TestHelpListsCommands(t *testing.T) {
	for _, arg := range []string{"help", "-h", "--help"} {
		t.Run(arg, func(t *testing.T) {
			e, out, _ := testEnv(nil)

			code := e.run([]string{"ramparteye", arg})

			assert.Equal(t, 0, code)
			for _, name := range []string{"serve", "scan", "verify", "import", "export", "migrate",
				"seed-demo", "audit", "dojo", "reset-admin", "version"} {
				assert.Contain(t, "\n  "+name+" ", out.String())
			}
		})
	}
}

func TestRunWithoutCommandPrintsUsage(t *testing.T) {
	e, out, errb := testEnv(nil)

	code := e.run([]string{"ramparteye"})

	assert.Equal(t, 2, code)
	assert.Equal(t, "", out.String())
	assert.Contain(t, "usage: ramparteye <command>", errb.String())
}

func TestInvalidConfigExits2(t *testing.T) {
	e, _, errb := testEnv(map[string]string{"RAMPART_ALLOWED_CIDRS": "10.0.0.0/33"})

	code := e.run([]string{"ramparteye", "migrate"})

	assert.Equal(t, 2, code)
	assert.Contain(t, "ramparteye: configuration: RAMPART_ALLOWED_CIDRS", errb.String())
}
