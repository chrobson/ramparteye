package diff

import (
	"strconv"

	"github.com/chrobson/ramparteye/internal/model"
)

// GatewayField is the Field of the single "changed" row emitted when a
// service starts or stops answering with a gateway error.
const GatewayField = "http_status"

// IsGatewayError reports whether an HTTP status is a reverse proxy's own
// answer for an unreachable upstream (502, 503, 504).
func IsGatewayError(status int) bool { return status == 502 || status == 503 || status == 504 }

// fingerprintFields describe whoever answered on the port. When the upstream
// behind a reverse proxy dies, the proxy itself answers and the scanner
// fingerprints the proxy instead.
var fingerprintFields = map[string]bool{
	"product": true, "version": true, "extrainfo": true, "cpe": true, "banner": true,
}

// CollapseGateway rewrites the changes of services whose HTTP status moved
// into or out of a gateway error (see IsGatewayError): their fingerprint
// "changed" rows are dropped and replaced by one row with Field GatewayField
// ("200" -> "502"). The port is open and the service is the same; what
// changed is the health of the upstream. status maps service ids (of either
// run) to their HTTP status; services without an HTTP status are untouched.
func CollapseGateway(prev, curr []model.ServiceObs, status map[int64]int, changes []model.Change) []model.Change {
	if len(status) == 0 {
		return changes
	}
	pm := make(map[model.AssetKey]int64, len(prev))
	for _, s := range prev {
		pm[normKey(s.Key)] = s.ID
	}
	flipped := map[model.AssetKey][2]int{}
	for _, c := range curr {
		k := normKey(c.Key)
		pid, ok := pm[k]
		if !ok {
			continue
		}
		o, okO := status[pid]
		n, okN := status[c.ID]
		if okO && okN && IsGatewayError(o) != IsGatewayError(n) {
			flipped[k] = [2]int{o, n}
		}
	}
	if len(flipped) == 0 {
		return changes
	}
	out := changes[:0]
	for _, ch := range changes {
		if _, ok := flipped[normKey(ch.Key)]; ok && ch.Kind == model.ChangeChanged && fingerprintFields[ch.Field] {
			continue
		}
		out = append(out, ch)
	}
	for k, st := range flipped {
		out = append(out, model.Change{
			Kind: model.ChangeChanged, Key: k, Field: GatewayField,
			Old: strconv.Itoa(st[0]), New: strconv.Itoa(st[1]),
		})
	}
	return out
}
