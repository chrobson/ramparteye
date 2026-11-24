package httpfp

import (
	"net/http"
	"testing"

	"github.com/ctx42/testing/pkg/assert"
)

func Test_IsSensitiveHeader(t *testing.T) {
	for _, n := range []string{
		"Authorization", "proxy-authorization", "Cookie", "X-Auth-Token",
		"X-Api-Key", "X-Session-Id", "X-Secret", "X-Password",
	} {
		assert.True(t, IsSensitiveHeader(n), n)
	}
	for _, n := range []string{"Server", "Content-Type", "X-Powered-By"} {
		assert.False(t, IsSensitiveHeader(n), n)
	}
}

func Test_cleanHeaders(t *testing.T) {
	h := http.Header{}
	h.Add("Server", "nginx")
	h.Add("Set-Cookie", "sid=SECRET")
	h.Add("X-Auth-Token", "SECRET")
	h.Add("WWW-Authenticate", `Basic realm="x"`)

	got := cleanHeaders(h)

	assert.Equal(t, []string{"nginx"}, got["Server"])
	_, ok := got["Set-Cookie"]
	assert.False(t, ok)
	assert.Equal(t, []string{redacted}, got["X-Auth-Token"])
	assert.Equal(t, []string{`Basic realm="x"`}, got["Www-Authenticate"])
}
