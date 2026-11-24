package store_test

import (
	"github.com/chrobson/ramparteye/internal/bootstrap"
	"github.com/chrobson/ramparteye/internal/store"
)

var _ bootstrap.Store = (*store.Store)(nil)
