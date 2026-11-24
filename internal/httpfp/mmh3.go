package httpfp

import (
	"encoding/base64"
	"math/bits"
)

// Sum32 is MurmurHash3 x86 32-bit with the given seed. Own implementation so
// favicon hashes stay compatible with Shodan / httpx (mmh3.hash, seed 0).
func Sum32(data []byte, seed uint32) uint32 {
	const (
		c1 = 0xcc9e2d51
		c2 = 0x1b873593
	)
	h := seed
	n := len(data)
	nblocks := n / 4
	for i := 0; i < nblocks; i++ {
		b := data[i*4:]
		k := uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
		k *= c1
		k = bits.RotateLeft32(k, 15)
		k *= c2
		h ^= k
		h = bits.RotateLeft32(h, 13)
		h = h*5 + 0xe6546b64
	}
	tail := data[nblocks*4:]
	var k uint32
	switch len(tail) {
	case 3:
		k ^= uint32(tail[2]) << 16
		fallthrough
	case 2:
		k ^= uint32(tail[1]) << 8
		fallthrough
	case 1:
		k ^= uint32(tail[0])
		k *= c1
		k = bits.RotateLeft32(k, 15)
		k *= c2
		h ^= k
	}
	h ^= uint32(n)
	h ^= h >> 16
	h *= 0x85ebca6b
	h ^= h >> 13
	h *= 0xc2b2ae35
	h ^= h >> 16
	return h
}

// ShodanBase64 encodes data like Python's base64.encodebytes: standard
// alphabet, a newline after every 76 output characters and a trailing newline.
func ShodanBase64(data []byte) []byte {
	if len(data) == 0 {
		return []byte{}
	}
	enc := base64.StdEncoding.EncodeToString(data)
	out := make([]byte, 0, len(enc)+len(enc)/76+1)
	for len(enc) > 76 {
		out = append(out, enc[:76]...)
		out = append(out, '\n')
		enc = enc[76:]
	}
	out = append(out, enc...)
	out = append(out, '\n')
	return out
}

// FaviconHash returns the Shodan-compatible favicon hash (http.favicon.hash):
// signed 32-bit mmh3 (seed 0) over ShodanBase64(raw favicon bytes).
func FaviconHash(raw []byte) int32 {
	return int32(Sum32(ShodanBase64(raw), 0))
}
