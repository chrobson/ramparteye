package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/ctx42/testing/pkg/assert"

	"github.com/chrobson/ramparteye/internal/diff"
	"github.com/chrobson/ramparteye/internal/exchange"
)

func writeFile(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	assert.NoError(t, os.WriteFile(p, []byte(content), 0o600))
	return p
}

func TestImportResultsUsesExchange(t *testing.T) {
	e, out, _ := testEnv(map[string]string{"RAMPART_ALLOWED_CIDRS": "10.0.0.0/24", "RAMPART_INACTIVE_AFTER_MISSES": "4"})
	x := &fakeExchange{rep: exchange.Report{RunID: 5, Format: exchange.FormatNmapXML, Hosts: 2, Services: 3}}
	withExchange(e, x)
	path := writeFile(t, "scan.xml", `<?xml version="1.0"?><nmaprun scanner="nmap"></nmaprun>`)

	code := e.run([]string{"ramparteye", "import", path})

	assert.Equal(t, 0, code)
	assert.Contain(t, "nmaprun", string(x.imported))
	assert.True(t, x.scope.Allows(mustAddr("10.0.0.9")))
	assert.Equal(t, diff.Config{InactiveAfterMisses: 4, UnstableIfFlips: 2, Window: 5}, x.unstable)
	var rep exchange.Report
	assert.NoError(t, json.Unmarshal(out.Bytes(), &rep))
	assert.Equal(t, int64(5), rep.RunID)
}

func TestImportWithoutScopeExits2(t *testing.T) {
	e, _, errb := testEnv(nil)
	x := &fakeExchange{}
	withExchange(e, x)
	path := writeFile(t, "scan.xml", `<nmaprun></nmaprun>`)

	code := e.run([]string{"ramparteye", "import", path})

	assert.Equal(t, 2, code)
	assert.Nil(t, x.imported)
	assert.Contain(t, "no scan scope configured: set RAMPART_ALLOWED_CIDRS", errb.String())
}

func TestImportErrors(t *testing.T) {
	scope := map[string]string{"RAMPART_ALLOWED_CIDRS": "10.0.0.0/24"}
	t.Run("usage", func(t *testing.T) {
		e, _, errb := testEnv(scope)
		assert.Equal(t, 2, e.run([]string{"ramparteye", "import"}))
		assert.Contain(t, "usage: ramparteye import <file>", errb.String())
	})
	t.Run("missing file", func(t *testing.T) {
		e, _, errb := testEnv(scope)
		withExchange(e, &fakeExchange{})
		assert.Equal(t, 1, e.run([]string{"ramparteye", "import", filepath.Join(t.TempDir(), "none.xml")}))
		assert.Contain(t, "ramparteye: import:", errb.String())
	})
	t.Run("import failure prints report", func(t *testing.T) {
		e, out, errb := testEnv(scope)
		withExchange(e, &fakeExchange{rep: exchange.Report{Dropped: 2}, importErr: exchange.ErrNothingToImport})
		path := writeFile(t, "scan.xml", `<nmaprun></nmaprun>`)

		assert.Equal(t, 1, e.run([]string{"ramparteye", "import", path}))
		assert.Contain(t, `"dropped": 2`, out.String())
		assert.Contain(t, "ramparteye: import: nothing to import", errb.String())
	})
}
