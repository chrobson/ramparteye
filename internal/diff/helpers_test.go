package diff

import (
	"fmt"
	"net/netip"

	"github.com/chrobson/ramparteye/internal/model"
)

var testCfg = Config{InactiveAfterMisses: 3, UnstableIfFlips: 2, Window: 5}

func ip(s string) netip.Addr { return netip.MustParseAddr(s) }

func svc(run int64, addr string, port uint16, product, version string) model.ServiceObs {
	return model.ServiceObs{
		RunID: run, Product: product, Version: version,
		Key: model.AssetKey{IP: ip(addr), Port: port, Proto: "tcp"},
	}
}

func keyString(k model.AssetKey) string {
	if k.Port == 0 {
		return k.IP.String()
	}
	s := netip.AddrPortFrom(k.IP, k.Port).String() + "/" + k.Proto
	if k.VHost != "" {
		s += " (" + k.VHost + ")"
	}
	return s
}

func fmtChange(c model.Change) string {
	s := fmt.Sprintf("%s %s", c.Kind, keyString(c.Key))
	if c.Field != "" {
		s += " " + c.Field
	}
	if c.Old != "" || c.New != "" {
		s += fmt.Sprintf(" %q->%q", c.Old, c.New)
	}
	return s
}

func fmtChanges(cs []model.Change) []string {
	out := []string{}
	for _, c := range cs {
		out = append(out, fmtChange(c))
	}
	return out
}
