package httpfp

import (
	"testing"

	"github.com/ctx42/testing/pkg/assert"
)

func Test_Sum32_vectors(t *testing.T) {
	tests := []struct {
		in   string
		seed uint32
		want uint32
	}{
		{"hello", 0, 0x248bfa47},
		{"", 0, 0},
		{"", 1, 0x514e28b7},
		{"The quick brown fox jumps over the lazy dog", 0, 0x2e4ff723},
		{"a", 0, 0x3c2569b2},
		{"ab", 0, 0x9bbfd75f},
		{"abc", 0, 0xb3dd93fa},
		{"abcd", 0, 0x43ed676a},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			assert.Equal(t, tc.want, Sum32([]byte(tc.in), tc.seed))
		})
	}
}

func Test_ShodanBase64(t *testing.T) {
	t.Run("matches python encodebytes", func(t *testing.T) {
		d := make([]byte, 100)
		for i := range d {
			d[i] = byte(i)
		}
		want := "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4\n" +
			"OTo7PD0+P0BBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV5fYGFiYw==\n"

		assert.Equal(t, want, string(ShodanBase64(d)))
	})

	t.Run("exactly 76 chars has one trailing newline", func(t *testing.T) {
		want := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"

		assert.Equal(t, want, string(ShodanBase64(make([]byte, 57))))
	})

	t.Run("empty", func(t *testing.T) {
		assert.Len(t, 0, ShodanBase64(nil))
	})
}

func Test_FaviconHash(t *testing.T) {
	raw := []byte("\x00\x00\x01\x00fake-icon")

	assert.Equal(t, int32(Sum32(ShodanBase64(raw), 0)), FaviconHash(raw))
}
