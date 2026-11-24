package diff

import (
	"testing"

	"github.com/ctx42/testing/pkg/assert"

	"github.com/chrobson/ramparteye/internal/model"
)

func TestGatewayErrorCollapsed(t *testing.T) {
	key := func(p uint16) model.AssetKey { return model.AssetKey{IP: ip("127.0.0.1"), Port: p, Proto: "tcp"} }
	prev := []model.ServiceObs{
		{ID: 1, Key: key(8085), Product: "Apache httpd", Version: "2.4.71", Banner: "http"},
		{ID: 2, Key: key(8888), Product: "nginx", Version: "1.27"},
	}
	curr := []model.ServiceObs{
		{ID: 11, Key: key(8085), Product: "Golang net/http server", Banner: "ssl/http"},
		{ID: 12, Key: key(8888), Product: "nginx", Version: "1.29"},
	}
	status := map[int64]int{1: 302, 11: 502, 2: 200, 12: 200}

	have := CollapseGateway(prev, curr, status, CompareServices(prev, curr))
	SortChanges(have)

	assert.Equal(t, []string{
		`changed 127.0.0.1:8085/tcp http_status "302"->"502"`,
		`changed 127.0.0.1:8888/tcp version "1.27"->"1.29"`,
	}, fmtChanges(have))
}

func TestGatewayRecoveryAndNoStatus(t *testing.T) {
	key := model.AssetKey{IP: ip("127.0.0.1"), Port: 8085, Proto: "tcp"}
	bad := []model.ServiceObs{{ID: 11, Key: key, Product: "proxy"}}
	good := []model.ServiceObs{{ID: 1, Key: key, Product: "Apache httpd"}}

	back := CollapseGateway(bad, good, map[int64]int{11: 502, 1: 302}, CompareServices(bad, good))
	assert.Equal(t, []string{`changed 127.0.0.1:8085/tcp http_status "502"->"302"`}, fmtChanges(back))

	untouched := CollapseGateway(good, bad, nil, CompareServices(good, bad))
	assert.Len(t, 1, untouched)
	assert.Equal(t, "product", untouched[0].Field)
	assert.True(t, IsGatewayError(504))
	assert.False(t, IsGatewayError(500))
}
