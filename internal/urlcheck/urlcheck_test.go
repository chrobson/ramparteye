package urlcheck

import (
	"strings"
	"testing"

	"github.com/ctx42/testing/pkg/assert"
)

func TestParse(t *testing.T) {
	ok := map[string]string{
		"HTTPS://Dojo.Example/Base//":   "https://dojo.example/Base//",
		" http://DOJO.example:8080/ ":   "http://dojo.example:8080/",
		"http://[::1]:8080/dojo/":       "http://[::1]:8080/dojo/",
		"http://[2001:DB8::1]":          "http://[2001:db8::1]",
		"https://hooks.example/T0/B1/x": "https://hooks.example/T0/B1/x",
	}
	for in, want := range ok {
		u, err := Parse(in, false)
		assert.NoError(t, err, in)
		assert.Equal(t, want, u.String(), in)
	}
	for _, in := range []string{
		"", "http:/host", "http://user@host", "http://@host", "http://host:", "http://host:0",
		"http://host:65536", "http://host:99999", "http://host:abc", "http://:8080", "ftp://host",
		"host/path", "http://host/?q=1", "http://host/#frag", "http://host/?", "://pw:%zz",
	} {
		_, err := Parse(in, false)
		assert.Error(t, err, in)
	}
}

func TestParseAllowQuery(t *testing.T) {
	u, err := Parse("https://Flow.Example/run?sig=abc&v=1", true)
	assert.NoError(t, err)
	assert.Equal(t, "https://flow.example/run?sig=abc&v=1", u.String())

	_, err = Parse("https://flow.example/run?sig=abc#frag", true)
	assert.Error(t, err)
	_, err = Parse("https://user:pw@flow.example/run?sig=abc", true)
	assert.Error(t, err)
}

func TestParseErrorsNeverEchoInput(t *testing.T) {
	for _, in := range []string{
		"https://user:SECRETPW@h.example/", "https://h.example/?api_key=SECRETKEY",
		"ftp://user:SECRETPW@h.example/?api_key=SECRETKEY", "https://h.example/#SECRETKEY", "://SECRETPW:%zz",
		"https://h.example:SECRETPORT/SECRETPATH",
	} {
		_, err := Parse(in, false)
		assert.Error(t, err, in)
		assert.False(t, strings.Contains(err.Error(), "SECRET"), in)
	}
}

func TestOrigin(t *testing.T) {
	u, err := Parse("HTTPS://Hooks.Example:8443/services/T0/B1/SECRET?x=1", true)
	assert.NoError(t, err)

	assert.Equal(t, "https://hooks.example:8443", Origin(u))
	assert.Equal(t, "", Origin(nil))
}
