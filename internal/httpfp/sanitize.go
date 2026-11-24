package httpfp

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

func validUTF8(s string) bool { return utf8.ValidString(s) }

// clean makes s safe to store: valid UTF-8, control characters dropped, at
// most max bytes (cut on a rune boundary).
func clean(s string, max int) string {
	if len(s) > max*4 {
		s = s[:max*4] // bound the work on hostile input
	}
	s = strings.ToValidUTF8(s, "�")
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
	if len(s) > max {
		s = s[:max]
		for !utf8.ValidString(s) {
			s = s[:len(s)-1]
		}
	}
	return s
}
