package web

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/ctx42/testing/pkg/assert"

	"github.com/chrobson/ramparteye/internal/auth"
	"github.com/chrobson/ramparteye/internal/model"
)

func targetsEnv(t *testing.T, opts ...envOpt) *testEnv {
	t.Helper()
	e := newEnv(t, opts...)
	e.st.dash.targets = []model.Target{
		{ID: 1, Kind: model.TargetCIDR, Value: "10.20.0.0/24", Tags: []string{"lab", "web"}},
		{ID: 2, Kind: model.TargetIP, Value: "10.20.9.9", Tags: []string{"db"}},
	}
	return e
}

func TestTargetImportOutOfScopeReported(t *testing.T) {
	e := targetsEnv(t)
	csv := "value,tags\n10.20.1.5,lab\n192.168.1.1,\n10.20.0.0/24,\n"

	rec := e.upload("/targets/import", "file", "targets.csv", []byte(csv), nil, e.login(t, auth.RoleOperator))
	body := rec.Body.String()

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contain(t, "Refused", body)
	assert.Contain(t, "192.168.1.1", body)
	assert.Contain(t, "outside the allowed scan scope", body)
	assert.Contain(t, "1 added", body)
	assert.Contain(t, "1 already present", body)
	assert.Equal(t, []string{"10.20.0.0/24", "10.20.9.9", "10.20.1.5"}, e.st.targetValues())
	assert.Equal(t, "targets.import", e.st.lastAudit().Action)
}

func TestTargetImportJSON(t *testing.T) {
	e := targetsEnv(t)
	js := `[{"value": "10.20.2.0/25", "tags": ["new"]}, {"value": "8.8.8.8"}]`

	rec := e.upload("/targets/import", "file", "t.json", []byte(js), map[string]string{"tags": "batch"},
		e.login(t, auth.RoleOperator))

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contain(t, "8.8.8.8", rec.Body.String())
	assert.Equal(t, []string{"10.20.0.0/24", "10.20.9.9", "10.20.2.0/25"}, e.st.targetValues())
	assert.Equal(t, []string{"new", "batch"}, e.st.dash.targets[2].Tags)
}

func TestTargetImportInvalidFile(t *testing.T) {
	e := targetsEnv(t)
	csv := "10.20.1.5\nnot a target!!\n"

	rec := e.upload("/targets/import", "file", "t.csv", []byte(csv), nil, e.login(t, auth.RoleOperator))

	assert.Equal(t, http.StatusUnprocessableEntity, rec.Code)
	assert.Contain(t, "line 2", rec.Body.String())
	assert.Len(t, 2, e.st.dash.targets)
}

func TestTargetImportNoScope(t *testing.T) {
	e := targetsEnv(t, withNoScope())

	rec := e.upload("/targets/import", "file", "t.csv", []byte("10.20.1.5\n"), nil, e.login(t, auth.RoleOperator))

	assert.Equal(t, http.StatusUnprocessableEntity, rec.Code)
	assert.Contain(t, "No scan scope configured", rec.Body.String())
	assert.Len(t, 2, e.st.dash.targets)
}

func TestTargetImportMissingFile(t *testing.T) {
	e := targetsEnv(t)

	rec := e.post("/targets/import", url.Values{"tags": {"x"}}, e.login(t, auth.RoleOperator))

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contain(t, "Choose a CSV or JSON file", rec.Body.String())
}

func TestTargetAddForm(t *testing.T) {
	e := targetsEnv(t)
	form := url.Values{"values": {"10.20.3.0/24 web;prod\n# comment\n\nnot a target!!\n172.16.0.1\n"},
		"tags": {"manual"}}

	rec := e.post("/targets", form, e.login(t, auth.RoleOperator))
	body := rec.Body.String()

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contain(t, "1 added", body)
	assert.Contain(t, "not a target!!", body)
	assert.Contain(t, "172.16.0.1", body)
	assert.Equal(t, []string{"10.20.0.0/24", "10.20.9.9", "10.20.3.0/24"}, e.st.targetValues())
	assert.Equal(t, []string{"web", "prod", "manual"}, e.st.dash.targets[2].Tags)
}

func TestTargetAddDomainResolvingOutOfScope(t *testing.T) {
	e := targetsEnv(t, withResolver(map[string][]string{
		"app.lab.test":  {"10.20.5.5"},
		"evil.lab.test": {"10.20.5.6", "203.0.113.9"},
	}))

	rec := e.post("/targets", url.Values{"values": {"app.lab.test\nevil.lab.test"}}, e.login(t, auth.RoleOperator))
	body := rec.Body.String()

	assert.Contain(t, "evil.lab.test", body)
	assert.Contain(t, "203.0.113.9", body)
	assert.Equal(t, []string{"10.20.0.0/24", "10.20.9.9", "app.lab.test"}, e.st.targetValues())
}

func TestTargetAddPartlyOutOfScopeCIDR(t *testing.T) {
	e := targetsEnv(t)

	rec := e.post("/targets", url.Values{"values": {"10.20.0.0/16"}}, e.login(t, auth.RoleOperator))

	assert.Contain(t, "10.20.0.0/16", rec.Body.String())
	assert.Contain(t, "outside the allowed scan scope", rec.Body.String())
	assert.Len(t, 2, e.st.dash.targets)
}

func TestTargetAddNoScope(t *testing.T) {
	e := targetsEnv(t, withNoScope())

	rec := e.post("/targets", url.Values{"values": {"10.20.3.0/24"}}, e.login(t, auth.RoleOperator))

	assert.Equal(t, http.StatusUnprocessableEntity, rec.Code)
	assert.Contain(t, "No scan scope configured", rec.Body.String())
}

func TestTargetsPage(t *testing.T) {
	e := targetsEnv(t, func(d *Deps) {
		withScope("10.20.0.0/18")(d)
	})

	viewer := e.get("/targets", e.login(t, auth.RoleViewer))
	body := viewer.Body.String()
	assert.Equal(t, http.StatusOK, viewer.Code)
	assert.Contain(t, "10.20.0.0/18", body)
	assert.Contain(t, "10.20.0.0/24", body)
	assert.Contain(t, "256", body)
	assert.NotContain(t, `action="/targets/import"`, body)

	op := e.get("/targets", e.login(t, auth.RoleOperator)).Body.String()
	assert.Contain(t, `action="/targets/import"`, op)
	assert.Contain(t, `action="/targets/1/tags"`, op)
}

func TestTargetsNoScopeBanner(t *testing.T) {
	e := targetsEnv(t, withNoScope())

	body := e.get("/targets", e.login(t, auth.RoleOperator)).Body.String()

	assert.Contain(t, "No scan scope configured", body)
}

func TestTargetsFilterByTag(t *testing.T) {
	e := targetsEnv(t)
	c := e.login(t, auth.RoleViewer)

	body := e.get("/targets?tag=db", c).Body.String()
	assert.Contain(t, "10.20.9.9", body)
	assert.NotContain(t, ">10.20.0.0/24<", body)

	assert.Equal(t, http.StatusBadRequest, e.get("/targets?tag=%3Dcmd", c).Code)
}

func TestTargetTagsAndDelete(t *testing.T) {
	e := targetsEnv(t)
	c := e.login(t, auth.RoleOperator)

	rec := e.post("/targets/2/tags", url.Values{"tags": {"DB; Prod"}}, c)
	assert.Equal(t, http.StatusSeeOther, rec.Code)
	assert.Equal(t, []string{"db", "prod"}, e.st.dash.targets[1].Tags)

	rec = e.post("/targets/2/tags", url.Values{"tags": {"=evil"}}, c)
	assert.Equal(t, http.StatusSeeOther, rec.Code)
	assert.Contain(t, "must not start with", flashOf(t, rec))

	rec = e.post("/targets/2/delete", nil, c)
	assert.Equal(t, http.StatusSeeOther, rec.Code)
	assert.Equal(t, []string{"10.20.0.0/24"}, e.st.targetValues())
	assert.Equal(t, "targets.delete", e.st.lastAudit().Action)

	assert.Equal(t, http.StatusNotFound, e.post("/targets/9/delete", nil, c).Code)
	assert.Equal(t, http.StatusNotFound, e.post("/targets/x/tags", nil, c).Code)
}

func TestTargetWritesNeedTargetsWrite(t *testing.T) {
	e := targetsEnv(t)
	c := e.login(t, auth.RoleAnalyst)

	assert.Equal(t, http.StatusForbidden, e.post("/targets", url.Values{"values": {"10.20.3.1"}}, c).Code)
	assert.Equal(t, http.StatusForbidden, e.post("/targets/1/delete", nil, c).Code)
	assert.Equal(t, http.StatusForbidden,
		e.upload("/targets/import", "file", "t.csv", []byte("10.20.1.1\n"), nil, c).Code)
	assert.Len(t, 2, e.st.dash.targets)
}
