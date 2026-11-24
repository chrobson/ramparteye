package runner

import (
	"testing"
	"time"

	"github.com/ctx42/testing/pkg/assert"
)

func TestSizer(t *testing.T) {
	cases := []struct {
		name string
		obs  [][2]float64 // addresses, seconds
		want int
	}{
		{"initial", nil, 256},
		{"fast network grows to max", [][2]float64{{256, 2}}, 4096},    // 90/(2/256)=11520 -> 4096
		{"slow network shrinks to min", [][2]float64{{256, 1200}}, 64}, // 90/4.69=19 -> 64
		{"target hit", [][2]float64{{256, 45}}, 512},                   // 90/(45/256)=512
		{"rounds down to a power of two", [][2]float64{{256, 60}}, 256},
		{"ewma smooths", [][2]float64{{256, 45}, {256, 90}}, 256}, // 0.1758 -> 0.2285 s/addr -> 393 -> 256
		{"zero duration", [][2]float64{{256, 0}}, 4096},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := NewSizer(0, 0)
			for _, o := range c.obs {
				s.Observe(int(o[0]), time.Duration(o[1]*float64(time.Second)))
			}
			assert.Equal(t, c.want, s.Next())
		})
	}
}

func TestSizerCustomAndIgnoredObservations(t *testing.T) {
	s := NewSizer(1000, 30*time.Second)
	assert.Equal(t, 512, s.Next()) // 1000 rounds down to a power of two
	s.Observe(0, time.Second)
	s.Observe(10, -time.Second)
	assert.Equal(t, 512, s.Next()) // invalid observations are ignored
	s.Observe(512, 60*time.Second) // 30 s / (60/512 s per address) = 256
	assert.Equal(t, 256, s.Next())
}
