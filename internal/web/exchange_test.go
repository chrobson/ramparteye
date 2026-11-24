package web

import (
	"bytes"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/ctx42/testing/pkg/assert"

	"github.com/chrobson/ramparteye/internal/auth"
	"github.com/chrobson/ramparteye/internal/dojo"
	"github.com/chrobson/ramparteye/internal/exchange"
	"github.com/chrobson/ramparteye/internal/model"
	"github.com/chrobson/ramparteye/internal/store"
)

func exchangeSnapshot() exchange.Snapshot {
	return exchange.Snapshot{RunID: 6, RunKind: "scan", Date: testNow.Add(-time.Hour),
		Services: []dojo.Service{{ServiceObs: model.ServiceObs{Key: svcKey("10.20.9.4", 80), Banner: "http",
			Product: "=cmd|' /C calc'!A0"}}}}
}

func TestExchangeImportReport(t *testing.T) {
	x := &fakeExchange{rep: exchange.Report{RunID: 9, Format: exchange.FormatNmapXML, Hosts: 3, Services: 7,
		Detections: 2, Dropped: 4, Warnings: []string{"<b>odd</b> host skipped"}, Errors: []string{"bad port"},
		ErrorsTruncated: 12}}
	e := newEnv(t, withExchange(x))

	rec := e.upload("/exchange/import", "file", "scan.xml", []byte("<nmaprun/>"), nil, e.login(t, auth.RoleOperator))
	body := rec.Body.String()

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, [][]byte{[]byte("<nmaprun/>")}, x.imported)
	assert.Contain(t, `Imported as run <a class="font-mono underline" href="/scans/9">#9</a>`, body)
	assert.Contain(t, `href="/scans/9"`, body)
	assert.Contain(t, "nmap XML", body)
	assert.Contain(t, "4 hosts outside the scan scope were dropped", body)
	assert.Contain(t, "&lt;b&gt;odd&lt;/b&gt; host skipped", body)
	assert.Contain(t, "bad port", body)
	assert.Contain(t, "and 12 more", body)
	assert.Equal(t, "results.import", e.st.lastAudit().Action)
}

func TestExchangeImportFailure(t *testing.T) {
	x := &fakeExchange{rep: exchange.Report{Dropped: 2}, err: exchange.ErrNothingToImport}
	e := newEnv(t, withExchange(x))

	rec := e.upload("/exchange/import", "file", "scan.xml", []byte("<nmaprun/>"), nil, e.login(t, auth.RoleOperator))

	assert.Equal(t, http.StatusUnprocessableEntity, rec.Code)
	assert.Contain(t, "Import failed: nothing to import", rec.Body.String())
	assert.Contain(t, "2 hosts outside the scan scope were dropped", rec.Body.String())
}

func TestExchangeImportNoScope(t *testing.T) {
	x := &fakeExchange{}
	e := newEnv(t, withExchange(x), withNoScope())

	rec := e.upload("/exchange/import", "file", "scan.xml", []byte("<nmaprun/>"), nil, e.login(t, auth.RoleOperator))

	assert.Equal(t, http.StatusUnprocessableEntity, rec.Code)
	assert.Contain(t, "No scan scope configured", rec.Body.String())
	assert.Len(t, 0, x.imported)
}

func TestExchangeImportTooLarge(t *testing.T) {
	x := &fakeExchange{}
	e := newEnv(t, withExchange(x))
	big := bytes.Repeat([]byte(" "), exchange.MaxImportSize+1)

	rec := e.upload("/exchange/import", "file", "scan.xml", big, nil, e.login(t, auth.RoleOperator))

	assert.Equal(t, http.StatusRequestEntityTooLarge, rec.Code)
	assert.Contain(t, "larger than 32 MiB", rec.Body.String())
	assert.Len(t, 0, x.imported)
}

func TestExchangeImportNeedsScansRun(t *testing.T) {
	x := &fakeExchange{}
	e := newEnv(t, withExchange(x))
	c := e.login(t, auth.RoleAnalyst)

	rec := e.upload("/exchange/import", "file", "scan.xml", []byte("<nmaprun/>"), nil, c)

	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Len(t, 0, x.imported)
	assert.NotContain(t, `action="/exchange/import"`, e.get("/exchange", c).Body.String())
}

func TestExchangePage(t *testing.T) {
	x := &fakeExchange{snap: exchangeSnapshot()}
	e := newEnv(t, withExchange(x))

	rec := e.get("/exchange", e.login(t, auth.RoleOperator))
	body := rec.Body.String()

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contain(t, `action="/exchange/import"`, body)
	assert.Contain(t, `href="/exchange/export.csv?run=6"`, body)
	assert.Contain(t, `href="/exchange/export.json?run=6"`, body)
	assert.Contain(t, "Run #6", body)
}

func TestExchangePageNoRun(t *testing.T) {
	x := &fakeExchange{snapErr: store.ErrRunNotFound}
	e := newEnv(t, withExchange(x))

	rec := e.get("/exchange", e.login(t, auth.RoleOperator))

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contain(t, "No finished run to export yet", rec.Body.String())
}

func TestExchangeExportCSV(t *testing.T) {
	x := &fakeExchange{snap: exchangeSnapshot()}
	e := newEnv(t, withExchange(x))

	rec := e.get("/exchange/export.csv?run=6", e.login(t, auth.RoleAnalyst))

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, []int64{6}, x.snapAsked)
	assert.Equal(t, "text/csv; charset=utf-8", rec.Header().Get("Content-Type"))
	assert.Equal(t, `attachment; filename="ramparteye-run-6-services.csv"`, rec.Header().Get("Content-Disposition"))
	assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
	assert.Contain(t, "ip,hostname,port", rec.Body.String())
	assert.Contain(t, "'=cmd", rec.Body.String())
	assert.Equal(t, "export.csv", e.st.lastAudit().Action)
}

func TestExchangeExportJSONLatest(t *testing.T) {
	x := &fakeExchange{snap: exchangeSnapshot()}
	e := newEnv(t, withExchange(x))

	rec := e.get("/exchange/export.json", e.login(t, auth.RoleAnalyst))

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, []int64{0}, x.snapAsked)
	assert.Equal(t, `attachment; filename="ramparteye-run-6-services.json"`, rec.Header().Get("Content-Disposition"))
	assert.Contain(t, `"tool": "ramparteye"`, rec.Body.String())
}

func TestExchangeExportErrors(t *testing.T) {
	x := &fakeExchange{snapErr: store.ErrRunNotFound}
	e := newEnv(t, withExchange(x))
	c := e.login(t, auth.RoleAnalyst)

	assert.Equal(t, http.StatusNotFound, e.get("/exchange/export.csv?run=99", c).Code)
	assert.Equal(t, http.StatusNotFound, e.get("/exchange/export.csv?run=abc", c).Code)
	assert.Equal(t, http.StatusNotFound, e.get("/exchange/export.json?run=-1", c).Code)
	assert.Equal(t, http.StatusForbidden, e.get("/exchange/export.csv", e.login(t, auth.RoleViewer)).Code)

	x.snapErr = errors.New("db down")
	assert.Equal(t, http.StatusInternalServerError, e.get("/exchange/export.csv", c).Code)
}

func TestExchangeWithoutBackend(t *testing.T) {
	e := newEnv(t)
	c := e.login(t, auth.RoleOperator)

	assert.Equal(t, http.StatusOK, e.get("/exchange", c).Code)
	rec := e.upload("/exchange/import", "file", "scan.xml", []byte("<nmaprun/>"), nil, c)
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}
