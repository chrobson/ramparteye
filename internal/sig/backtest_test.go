package sig

import (
	"context"
	"testing"

	"github.com/ctx42/testing/pkg/assert"
	"github.com/ctx42/testing/pkg/mock"

	"github.com/chrobson/ramparteye/internal/model"
)

// fetcherMock fails the test on any Fetch call without an expectation.
type fetcherMock struct{ *mock.Mock }

func (m fetcherMock) Fetch(_ context.Context, svc model.ServiceObs, _ model.HTTPObs, req ProbeRequest) (ProbeResponse, error) {
	m.Call("Fetch", svc.ID, req.Path)
	return ProbeResponse{Status: 200}, nil
}

func history() []Observation {
	nginx := httpObs(80, "Welcome", "", map[string][]string{"Server": {"nginx/1.25.3"}})
	plain := httpObs(8080, "It works", "", map[string][]string{"Server": {"Caddy"}})
	run1, run2 := svc(80, ""), svc(80, "")
	run1.RunID, run2.RunID = 1, 2
	run2.ID = 180
	other := svc(8080, "")
	other.RunID = 2
	return []Observation{{Service: run1, HTTP: nginx}, {Service: run2, HTTP: nginx}, {Service: other, HTTP: plain}}
}

func TestBacktestNoNetwork(t *testing.T) {
	s := mustParse(t, `id: bt-nginx
name: nginx or probe
category: server
confidence: 50
matchers:
  - {type: path, path: /status, status: [200]}
  - {type: header, name: Server, regex: 'nginx/(?P<version>[0-9.]+)'}
`)
	f := fetcherMock{mock.NewMock(t)}
	e := NewEngine([]*Signature{s}, f)

	res := e.Backtest(context.Background(), s, history())

	assert.True(t, f.AssertCallCount("Fetch", 0))
	assert.Equal(t, 3, res.Checked)
	assert.Equal(t, 1, res.PathMatchers)
	assert.Len(t, 2, res.Matches)
	assert.Equal(t, int64(1), res.Matches[0].RunID)
	assert.Equal(t, int64(2), res.Matches[1].RunID)
	assert.Equal(t, int64(180), res.Matches[1].Detection.ServiceID)
	assert.Equal(t, "1.25.3", res.Matches[1].Detection.Evidence["version"])
	assert.Equal(t, svc(80, "").Key, res.Matches[0].Key)
}

// A signature that needs a path probe to match never matches offline.
func TestBacktestPathOnlySignatureNeverMatches(t *testing.T) {
	s := mustParse(t, "id: bt-path\nname: P\ncategory: other\nconfidence: 5\nmatchers:\n  - {type: path, path: /x, status: [200]}\n")

	res := Backtest(context.Background(), s, history())

	assert.Equal(t, 3, res.Checked)
	assert.Len(t, 0, res.Matches)
	assert.Equal(t, 1, res.PathMatchers)
}

// Backtest evaluates the signature on its own: generic panels are not
// suppressed and disabled signatures are still tried.
func TestBacktestSingleSignature(t *testing.T) {
	s := mustParse(t, "id: login-page\nname: Login\ncategory: admin-panel\nconfidence: 5\nmatchers:\n  - {type: title, regex: Welcome}\n")
	s.Enabled = false

	res := Backtest(context.Background(), s, history())

	assert.Len(t, 2, res.Matches)
}

func TestBacktestStopsWhenContextDone(t *testing.T) {
	s := mustParse(t, "id: bt-any\nname: A\ncategory: other\nconfidence: 5\nmatchers:\n  - {type: status, status: [200]}\n")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	res := Backtest(ctx, s, history())

	assert.Equal(t, 0, res.Checked)
	assert.ErrorIs(t, context.Canceled, res.Err)
}
