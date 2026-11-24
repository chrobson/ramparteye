package exchange

import (
	"net/netip"
	"os"
	"testing"

	"github.com/ctx42/testing/pkg/must"

	"github.com/chrobson/ramparteye/internal/model"
	"github.com/chrobson/ramparteye/internal/scope"
)

func key(ip string, port uint16, proto string) model.AssetKey {
	return model.AssetKey{IP: netip.MustParseAddr(ip), Port: port, Proto: proto}
}

func readFile(t *testing.T, name string) []byte {
	t.Helper()
	return must.Value(os.ReadFile("testdata/" + name))
}

func labScope(t *testing.T) scope.Scope {
	t.Helper()
	return must.Value(scope.New([]netip.Prefix{netip.MustParsePrefix("10.20.0.0/24")}, nil, nil))
}
