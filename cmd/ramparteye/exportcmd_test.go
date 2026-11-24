package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/ctx42/testing/pkg/assert"

	"github.com/chrobson/ramparteye/internal/config"
	"github.com/chrobson/ramparteye/internal/diff"
	"github.com/chrobson/ramparteye/internal/dojo"
	"github.com/chrobson/ramparteye/internal/exchange"
	"github.com/chrobson/ramparteye/internal/model"
	"github.com/chrobson/ramparteye/internal/scope"
	"github.com/chrobson/ramparteye/internal/store"
	"github.com/chrobson/ramparteye/internal/web"
)

type fakeExchange struct {
	snap      exchange.Snapshot
	snapErr   error
	runID     int64
	rep       exchange.Report
	importErr error
	imported  []byte
	scope     scope.Scope
	unstable  diff.Config
}

func (f *fakeExchange) Import(_ context.Context, b []byte, s scope.Scope, cfg diff.Config, _ time.Time) (exchange.Report, error) {
	f.imported, f.scope, f.unstable = b, s, cfg
	return f.rep, f.importErr
}

func (f *fakeExchange) Snapshot(_ context.Context, runID int64) (exchange.Snapshot, error) {
	f.runID = runID
	return f.snap, f.snapErr
}

// withExchange makes e open x instead of the database.
func withExchange(e *env, x web.Exchange) {
	e.openExchange = func(context.Context, config.Config) (web.Exchange, func(), error) {
		return x, func() {}, nil
	}
}

func exportSnapshot() exchange.Snapshot {
	key := model.AssetKey{IP: netip.MustParseAddr("10.0.0.4"), Port: 80, Proto: "tcp"}
	return exchange.Snapshot{RunID: 6, RunKind: "scan", Date: time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC),
		Services: []dojo.Service{{ServiceObs: model.ServiceObs{Key: key, Product: "nginx"}}}}
}

func TestExportCSVStdout(t *testing.T) {
	e, out, errb := testEnv(nil)
	x := &fakeExchange{snap: exportSnapshot()}
	withExchange(e, x)

	code := e.run([]string{"ramparteye", "export", "--format", "csv"})

	assert.Equal(t, 0, code)
	assert.Equal(t, "", errb.String())
	assert.Equal(t, int64(0), x.runID)
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	assert.Len(t, 2, lines)
	assert.Equal(t, strings.Join(exchange.CSVHeader, ","), strings.TrimSpace(lines[0]))
	assert.Contain(t, "10.0.0.4", lines[1])
	assert.Contain(t, "nginx", lines[1])
}

func TestExportJSONAndDojo(t *testing.T) {
	for _, format := range []string{"json", "dojo"} {
		t.Run(format, func(t *testing.T) {
			e, out, _ := testEnv(nil)
			x := &fakeExchange{snap: exportSnapshot()}
			withExchange(e, x)

			code := e.run([]string{"ramparteye", "export", "--format", format, "--run", "6"})

			assert.Equal(t, 0, code)
			assert.Equal(t, int64(6), x.runID)
			assert.True(t, json.Valid(out.Bytes()))
			if format == "dojo" {
				assert.NoError(t, dojo.Validate(out.Bytes()))
			}
		})
	}
}

func TestExportErrors(t *testing.T) {
	for name, tc := range map[string]struct {
		args []string
		err  error
		code int
		want string
	}{
		"format":    {[]string{"--format", "xml"}, nil, 2, `unknown export format "xml" (csv, json or dojo)`},
		"bad run":   {[]string{"--run", "x"}, nil, 2, "invalid value"},
		"extra arg": {[]string{"csv"}, nil, 2, "usage: ramparteye export"},
		"no run":    {nil, store.ErrRunNotFound, 1, "ramparteye: export: no finished run to export"},
		"failure":   {nil, errors.New("boom"), 1, "ramparteye: export: boom"},
	} {
		t.Run(name, func(t *testing.T) {
			e, out, errb := testEnv(nil)
			withExchange(e, &fakeExchange{snapErr: tc.err})

			code := e.run(append([]string{"ramparteye", "export"}, tc.args...))

			assert.Equal(t, tc.code, code)
			assert.Equal(t, "", out.String())
			assert.Contain(t, tc.want, errb.String())
		})
	}
}
