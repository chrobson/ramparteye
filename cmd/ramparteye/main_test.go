package main

import (
	"bytes"
	"testing"

	"github.com/ctx42/testing/pkg/assert"
)

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
