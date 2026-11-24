package web

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"

	"github.com/ctx42/testing/pkg/assert"
	"github.com/ctx42/testing/pkg/must"

	"github.com/chrobson/ramparteye/internal/auth"
	"github.com/chrobson/ramparteye/internal/model"
	"github.com/chrobson/ramparteye/internal/sig"
	"github.com/chrobson/ramparteye/internal/store"
)

const customYAML = `id: acme-portal
name: ACME portal
category: other
confidence: 80
matchers:
  - type: title
    regex: 'ACME Portal'
`

func builtinRow(t *testing.T) store.SignatureRow {
	t.Helper()
	b := must.Value(os.ReadFile("../sig/builtin/adminer.yaml"))
	s := must.Value(sig.Parse(b))
	s.Source, s.Enabled = sig.SourceBuiltin, true
	return sig.Row(s)
}

func customRow(t *testing.T, yaml string) store.SignatureRow {
	t.Helper()
	s := must.Value(sig.Parse([]byte(yaml)))
	s.Source = sig.SourceCustom
	return sig.Row(s)
}

// uploadFiles sends a same-origin multipart POST with several files in one field.
func (e *testEnv) uploadFiles(path, field string, files map[string]string, c *http.Cookie) *httptest.ResponseRecorder {
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	for name, data := range files {
		fw := must.Value(mw.CreateFormFile(field, name))
		_, err := fw.Write([]byte(data))
		must.Nil(err)
	}
	must.Nil(mw.Close())
	req := httptest.NewRequest(http.MethodPost, path, &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.AddCookie(c)
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	return rec
}

func TestSignaturesList(t *testing.T) {
	e := newEnv(t)
	e.st.assets.sigs = []store.SignatureRow{builtinRow(t), customRow(t, customYAML)}

	body := e.get("/signatures", e.login(t, auth.RoleViewer)).Body.String()

	assert.Contain(t, `href="/signatures/adminer"`, body)
	assert.Contain(t, "ACME portal", body)
	assert.Contain(t, "built-in", body)
	assert.NotContain(t, `action="/signatures/adminer/toggle"`, body) // no signatures.write
}

func TestSignatureCreateInvalidKeepsInputEscaped(t *testing.T) {
	e := newEnv(t)
	bad := "id: x\nname: <script>alert(1)</script>\ncategory: nope\nconfidence: 80\nmatchers: []\n"

	rec := e.post("/signatures", url.Values{"yaml": {bad}}, e.login(t, auth.RoleOperator))

	assert.Equal(t, http.StatusUnprocessableEntity, rec.Code)
	body := rec.Body.String()
	assert.NotContain(t, "<script>alert(1)</script>", body)
	assert.Contain(t, "&lt;script&gt;alert(1)&lt;/script&gt;", body)
	assert.Contain(t, "category", body)
	assert.Len(t, 0, e.st.assets.sigs)
}

func TestSignatureCreate(t *testing.T) {
	e := newEnv(t)

	rec := e.post("/signatures", url.Values{"yaml": {customYAML}}, e.login(t, auth.RoleOperator))

	assert.Equal(t, http.StatusSeeOther, rec.Code)
	assert.Equal(t, "/signatures/acme-portal", rec.Header().Get("Location"))
	row, ok := e.st.sig("acme-portal")
	assert.True(t, ok)
	assert.Equal(t, sig.SourceCustom, row.Source)
	assert.True(t, row.Enabled)
	assert.Equal(t, "signature.create", e.st.lastAudit().Action)
}

func TestSignatureCreateDuplicateID(t *testing.T) {
	e := newEnv(t)
	e.st.assets.sigs = []store.SignatureRow{customRow(t, customYAML)}

	rec := e.post("/signatures", url.Values{"yaml": {customYAML}}, e.login(t, auth.RoleOperator))

	assert.Equal(t, http.StatusUnprocessableEntity, rec.Code)
	assert.Contain(t, "already exists", rec.Body.String())
}

func TestSignatureCreateNeedsWrite(t *testing.T) {
	e := newEnv(t)

	rec := e.post("/signatures", url.Values{"yaml": {customYAML}}, e.login(t, auth.RoleAnalyst))

	assert.Equal(t, http.StatusForbidden, rec.Code)
}

func TestSignatureUpdate(t *testing.T) {
	e := newEnv(t)
	e.st.assets.sigs = []store.SignatureRow{customRow(t, customYAML)}
	c := e.login(t, auth.RoleOperator)
	changed := "id: acme-portal\nname: ACME portal v2\ncategory: other\nconfidence: 80\nmatchers:\n  - type: title\n    regex: 'ACME'\n"

	rec := e.post("/signatures/acme-portal", url.Values{"yaml": {changed}}, c)

	assert.Equal(t, http.StatusSeeOther, rec.Code)
	row, _ := e.st.sig("acme-portal")
	assert.Equal(t, "ACME portal v2", row.Name)
	assert.Equal(t, "signature.update", e.st.lastAudit().Action)

	renamed := "id: other-id\nname: x\ncategory: other\nconfidence: 80\nmatchers:\n  - type: title\n    regex: 'x'\n"
	rec = e.post("/signatures/acme-portal", url.Values{"yaml": {renamed}}, c)
	assert.Equal(t, http.StatusUnprocessableEntity, rec.Code)
	assert.Contain(t, "cannot change", rec.Body.String())
}

func TestBuiltinSignatureNotEditable(t *testing.T) {
	e := newEnv(t)
	e.st.assets.sigs = []store.SignatureRow{builtinRow(t)}
	c := e.login(t, auth.RoleOperator)

	assert.Equal(t, http.StatusConflict, e.get("/signatures/adminer/edit", c).Code)
	assert.Equal(t, http.StatusConflict, e.post("/signatures/adminer", url.Values{"yaml": {customYAML}}, c).Code)
	assert.Equal(t, http.StatusConflict, e.post("/signatures/adminer/delete", nil, c).Code)
	body := e.get("/signatures/adminer", c).Body.String()
	assert.NotContain(t, `href="/signatures/adminer/edit"`, body)
	assert.Contain(t, `action="/signatures/adminer/toggle"`, body)
}

func TestSignatureToggle(t *testing.T) {
	e := newEnv(t)
	changed := 0
	e.srv.d.SignaturesChanged = func() { changed++ }
	e.st.assets.sigs = []store.SignatureRow{builtinRow(t)}

	rec := e.post("/signatures/adminer/toggle", nil, e.login(t, auth.RoleOperator))

	assert.Equal(t, http.StatusSeeOther, rec.Code)
	row, _ := e.st.sig("adminer")
	assert.False(t, row.Enabled)
	assert.Equal(t, "signature.disable", e.st.lastAudit().Action)
	assert.Equal(t, 1, changed)
}

func TestSignatureDelete(t *testing.T) {
	e := newEnv(t)
	e.st.assets.sigs = []store.SignatureRow{customRow(t, customYAML)}

	rec := e.post("/signatures/acme-portal/delete", nil, e.login(t, auth.RoleOperator))

	assert.Equal(t, http.StatusSeeOther, rec.Code)
	assert.Len(t, 0, e.st.assets.sigs)
	assert.Equal(t, "signature.delete", e.st.lastAudit().Action)
}

func TestSignatureBacktest(t *testing.T) {
	e := newEnv(t)
	e.st.assets.sigs = []store.SignatureRow{customRow(t, customYAML)}
	key := model.AssetKey{IP: mustAddr("10.20.0.5"), Port: 80, Proto: "tcp"}
	e.st.admin.history = []store.ObservedService{
		{Service: model.ServiceObs{ID: 1, RunID: 7, Key: key}, HTTP: model.HTTPObs{URL: "http://10.20.0.5/", Status: 200, Title: "ACME Portal <b>"}},
		{Service: model.ServiceObs{ID: 2, RunID: 7, Key: model.AssetKey{IP: mustAddr("10.20.0.6"), Port: 22, Proto: "tcp"}}},
	}

	rec := e.post("/signatures/acme-portal/backtest", nil, e.login(t, auth.RoleOperator))

	assert.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()
	assert.Contain(t, "1 match", body)
	assert.Contain(t, "2 observations", body)
	assert.Contain(t, "10.20.0.5", body)
	assert.NotContain(t, "10.20.0.6:22", body)
}

func TestSignatureBacktestDraft(t *testing.T) {
	e := newEnv(t)
	e.st.admin.history = []store.ObservedService{{Service: model.ServiceObs{ID: 1, RunID: 3,
		Key: model.AssetKey{IP: mustAddr("10.20.0.5"), Port: 80, Proto: "tcp"}},
		HTTP: model.HTTPObs{URL: "http://10.20.0.5/", Status: 200, Title: "ACME Portal"}}}

	rec := e.post("/signatures/backtest", url.Values{"yaml": {customYAML}}, e.login(t, auth.RoleOperator))

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contain(t, "1 match", rec.Body.String())
	assert.Contain(t, "acme-portal", rec.Body.String()) // the draft stays in the form
	assert.Len(t, 0, e.st.assets.sigs)                  // nothing stored
}

func TestNucleiImportReport(t *testing.T) {
	e := newEnv(t)
	good := string(must.Value(os.ReadFile("../nuclei/testdata/accept_server_status.yaml")))
	post := string(must.Value(os.ReadFile("../nuclei/testdata/reject_post.yaml")))

	rec := e.uploadFiles("/signatures/import", "files",
		map[string]string{"status.yaml": good, "post.yaml": post}, e.login(t, auth.RoleAdmin))

	assert.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()
	assert.Contain(t, "1 imported (disabled)", body)
	assert.Contain(t, "1 rejected", body)
	assert.Contain(t, "method POST not allowed", body)
	assert.Contain(t, "post.yaml", body)
	row, ok := e.st.sig("nuclei-apache-server-status-exposed")
	assert.True(t, ok)
	assert.False(t, row.Enabled)
	assert.Equal(t, sig.SourceNuclei, row.Source)
	assert.Equal(t, "signature.import", e.st.lastAudit().Action)
}

func TestNucleiImportIDCollision(t *testing.T) {
	e := newEnv(t)
	good := string(must.Value(os.ReadFile("../nuclei/testdata/accept_server_status.yaml")))
	existing := "id: nuclei-apache-server-status-exposed\nname: Mine\ncategory: other\nconfidence: 80\n" +
		"matchers:\n  - type: title\n    regex: 'x'\n"
	e.st.assets.sigs = []store.SignatureRow{customRow(t, existing)}

	rec := e.uploadFiles("/signatures/import", "files", map[string]string{"status.yaml": good}, e.login(t, auth.RoleAdmin))

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contain(t, "0 imported (disabled)", rec.Body.String())
	assert.Contain(t, "already exists", rec.Body.String())
	row, _ := e.st.sig("nuclei-apache-server-status-exposed")
	assert.Equal(t, "Mine", row.Name) // not overwritten
}

func TestNucleiImportAdminOnly(t *testing.T) {
	e := newEnv(t)

	rec := e.uploadFiles("/signatures/import", "files", map[string]string{"a.yaml": "id: a"}, e.login(t, auth.RoleOperator))

	assert.Equal(t, http.StatusForbidden, rec.Code)
}

func TestNucleiImportFileTooLarge(t *testing.T) {
	e := newEnv(t)
	big := string(bytes.Repeat([]byte("a"), 256<<10+1))

	rec := e.uploadFiles("/signatures/import", "files", map[string]string{"big.yaml": big}, e.login(t, auth.RoleAdmin))

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contain(t, "larger than 256 KiB", rec.Body.String())
}
