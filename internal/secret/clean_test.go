package secret

import (
	"strings"
	"testing"

	"github.com/ctx42/testing/pkg/assert"
)

func TestClean(t *testing.T) {
	v, err := Clean("  tok-123\n", "API token", 16)
	assert.NoError(t, err)
	assert.Equal(t, "tok-123", v)

	v, err = Clean("", "API token", 16)
	assert.NoError(t, err)
	assert.Equal(t, "", v)

	_, err = Clean(strings.Repeat("x", 17), "API token", 16)
	assert.ErrorEqual(t, "API token is longer than 16 bytes", err)

	for _, in := range []string{"a\tb", "a\x7fb", "a\u0085b", "a\x00b"} {
		_, err := Clean("SECRET"+in, "API token", 64)
		assert.ErrorEqual(t, "API token must not contain control characters", err)
	}
}
