package httpfp

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/ctx42/testing/pkg/assert"
)

func Test_ExtractTitle(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{"whitespace collapsed", "<title>a\n\tb</title>", "a b"},
		{"none", "<html>none</html>", ""},
		{"entities", "<TITLE> x &amp; y </TITLE>", "x & y"},
		{"script is text only", "<title><script>alert(1)</script></title>", "<script>alert(1)</script>"},
		{"control chars dropped", "<title>a\x00b\x1bc</title>", "abc"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, ExtractTitle([]byte(tc.body)))
		})
	}
}

func Test_ExtractTitle_invalid_utf8_sanitised(t *testing.T) {
	got := ExtractTitle([]byte("\xff<title>a\xfeb</title>"))

	assert.True(t, utf8.ValidString(got))
	assert.True(t, strings.HasPrefix(got, "a"))
	assert.True(t, strings.HasSuffix(got, "b"))
}

func Test_ExtractTitle_length(t *testing.T) {
	t.Run("ascii truncated to 512 runes", func(t *testing.T) {
		got := ExtractTitle([]byte("<title>" + strings.Repeat("a", 5000) + "</title>"))

		assert.Equal(t, 512, utf8.RuneCountInString(got))
	})

	t.Run("multibyte truncated on a rune boundary", func(t *testing.T) {
		got := ExtractTitle([]byte("<title>" + strings.Repeat("ż", 2000) + "</title>"))

		assert.Equal(t, 512, utf8.RuneCountInString(got))
		assert.True(t, utf8.ValidString(got))
	})
}

func Test_FaviconLinks(t *testing.T) {
	body := `<link rel="stylesheet" href="/a.css"><link href='/f.png' rel='icon'>` +
		`<link rel=mask-icon href=/m.svg><link rel="icon" href="data:,">`

	got := FaviconLinks([]byte(body))

	assert.Equal(t, []string{"/f.png"}, got)
}
