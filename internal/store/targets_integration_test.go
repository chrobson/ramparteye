//go:build integration

package store_test

import (
	"testing"

	"github.com/ctx42/testing/pkg/assert"
	"github.com/ctx42/testing/pkg/must"

	"github.com/chrobson/ramparteye/internal/model"
	"github.com/chrobson/ramparteye/internal/store"
)

func TestTargets(t *testing.T) {
	s, _ := newStore(t)
	ts := []model.Target{
		{Kind: model.TargetIP, Value: "192.0.2.7", Tags: []string{"it", "lab"}},
		{Kind: model.TargetDomain, Value: "app.lab.test", Tags: []string{"it"}},
		{Kind: model.TargetCIDR, Value: "10.0.0.0/24"},
	}

	var n int
	err := s.InTx(ctx, func(tx *store.Store) error {
		var err error
		n, err = tx.InsertTargets(ctx, ts, nil)
		return err
	})
	assert.NoError(t, err)
	assert.Equal(t, 3, n)
	assert.Equal(t, 0, must.Value(s.InsertTargets(ctx, ts, nil))) // duplicates skipped

	got := must.Value(s.Targets(ctx, "it"))
	assert.Len(t, 2, got)
	assert.Equal(t, model.TargetDomain, got[0].Kind) // ordered by kind, value
	assert.Equal(t, "192.0.2.7", got[1].Value)
	assert.Len(t, 3, must.Value(s.Targets(ctx, "")))
	assert.Equal(t, []string{"it", "lab"}, must.Value(s.TargetTags(ctx)))

	id := got[1].ID
	assert.NoError(t, s.UpdateTargetTags(ctx, id, []string{"edited"}))
	byID := must.Value(s.TargetsByIDs(ctx, []int64{id, -1}))
	assert.Len(t, 1, byID)
	assert.Equal(t, []string{"edited"}, byID[0].Tags)

	assert.Equal(t, "192.0.2.7", must.Value(s.DeleteTarget(ctx, id)))
	_, err = s.DeleteTarget(ctx, id)
	assert.ErrorIs(t, store.ErrTargetNotFound, err)
	assert.ErrorIs(t, store.ErrTargetNotFound, s.UpdateTargetTags(ctx, id, nil))
}

func TestInsertTargetsRollsBackInTx(t *testing.T) {
	s, _ := newStore(t)

	err := s.InTx(ctx, func(tx *store.Store) error {
		if _, err := tx.InsertTargets(ctx, []model.Target{{Kind: model.TargetIP, Value: "192.0.2.1"}}, nil); err != nil {
			return err
		}
		_, err := tx.InsertTargets(ctx, []model.Target{{Kind: "bogus", Value: "x"}}, nil)
		return err
	})

	assert.Error(t, err)
	assert.Len(t, 0, must.Value(s.Targets(ctx, "")))
}
