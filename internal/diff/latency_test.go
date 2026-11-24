package diff

import (
	"testing"

	"github.com/ctx42/testing/pkg/assert"

	"github.com/chrobson/ramparteye/internal/model"
)

func TestLatencyChangeBelow300Ignored(t *testing.T) {
	tests := []struct {
		old, new int
		want     bool
	}{
		{40, 45, false},     // jitter
		{40, 300, false},    // 7x but only +260 ms
		{40, 340, false},    // +300 ms is not above the threshold
		{40, 590, true},     // injected delay on a fast service
		{590, 40, true},     // delay removed
		{800, 1300, false},  // +500 ms but less than 2x
		{800, 1700, true},   // more than doubled and > 300 ms
		{2000, 2900, false}, // slow service, noisy
		{0, 900, false},     // not measured before
		{900, 0, false},     // not measured now
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, LatencyChanged(tt.old, tt.new))
	}
}

func TestLatencyChanges(t *testing.T) {
	mk := func(id, run int64, port uint16) model.ServiceObs {
		return model.ServiceObs{ID: id, RunID: run, Key: model.AssetKey{IP: ip("127.0.0.1"), Port: port, Proto: "tcp"}}
	}
	prev := []model.ServiceObs{mk(1, 1, 8080), mk(2, 1, 8085), mk(3, 1, 8888)}
	curr := []model.ServiceObs{mk(11, 2, 8080), mk(12, 2, 8085), mk(13, 2, 8888), mk(15, 2, 3001)}
	ms := map[int64]int{1: 35, 11: 41, 2: 30, 12: 1050, 3: 20, 15: 25}

	have := LatencyChanges(prev, curr, ms)

	assert.Len(t, 1, have)
	assert.Equal(t, uint16(8085), have[0].Key.Port)
	assert.Equal(t, LatencyField, have[0].Field)
	assert.Equal(t, "30 ms", have[0].Old)
	assert.Equal(t, "1050 ms", have[0].New)
	assert.Nil(t, LatencyChanges(prev, curr, nil))

	all := []model.Change{have[0], {Kind: model.ChangeChanged, Key: have[0].Key, Field: "version"}}
	SortChanges(all)
	assert.Equal(t, "version", all[0].Field)
	assert.Equal(t, LatencyField, all[1].Field)
}
