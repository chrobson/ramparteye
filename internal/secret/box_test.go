package secret

import (
	"bytes"
	"testing"

	"github.com/ctx42/testing/pkg/assert"
	"github.com/ctx42/testing/pkg/must"
)

func testKey() []byte { return bytes.Repeat([]byte{7}, 32) }

func TestSealOpenRoundTrip(t *testing.T) {
	box, err := NewBox(testKey())
	assert.NoError(t, err)

	ct, err := box.Seal([]byte("token-123"), "dojo:api")
	assert.NoError(t, err)
	assert.False(t, bytes.Contains(ct, []byte("token-123")))

	have, err := box.Open(ct, "dojo:api")
	assert.NoError(t, err)
	assert.Equal(t, "token-123", string(have))
}

func TestSealUsesFreshNonce(t *testing.T) {
	box := must.Value(NewBox(testKey()))
	a := must.Value(box.Seal([]byte("x"), "a"))
	b := must.Value(box.Seal([]byte("x"), "a"))
	assert.False(t, bytes.Equal(a, b))
}

func TestOpenWrongAAD(t *testing.T) {
	box := must.Value(NewBox(testKey()))
	ct := must.Value(box.Seal([]byte("x"), "right"))

	_, err := box.Open(ct, "wrong")

	assert.Error(t, err)
}

func TestOpenTamperedAndShort(t *testing.T) {
	box := must.Value(NewBox(testKey()))
	ct := must.Value(box.Seal([]byte("x"), "a"))
	ct[len(ct)-1] ^= 1

	_, err := box.Open(ct, "a")
	assert.Error(t, err)
	_, err = box.Open([]byte{1, 2}, "a")
	assert.Error(t, err)
}

func TestNewBoxRejectsBadKeySize(t *testing.T) {
	_, err := NewBox(make([]byte, 16))
	assert.Error(t, err)
}
