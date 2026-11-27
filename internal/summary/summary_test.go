package summary

import (
	"net/netip"
	"testing"

	"github.com/ctx42/testing/pkg/assert"

	"github.com/chrobson/ramparteye/internal/model"
	"github.com/chrobson/ramparteye/internal/store"
)

func key(ip string, port uint16) model.AssetKey {
	return model.AssetKey{IP: netip.MustParseAddr(ip), Port: port, Proto: "tcp"}
}

func TestCountChanges(t *testing.T) {
	cs := []model.Change{
		{Kind: model.ChangeNew, Key: key("10.0.0.1", 80)},
		{Kind: model.ChangeNew, Key: key("10.0.0.1", 443)},
		{Kind: model.ChangeGone, Key: key("10.0.0.2", 22)},
		{Kind: model.ChangeChanged, Key: key("10.0.0.3", 22)},
		{Kind: model.ChangeHostUp, Key: key("10.0.0.4", 0)},
		{Kind: model.ChangeHostDown, Key: key("10.0.0.5", 0)},
		{Kind: model.ChangeUnstable, Key: key("10.0.0.6", 0)},
	}

	c := CountChanges(cs)

	assert.Equal(t, Counts{NewHosts: 1, HostsGone: 1, NewServices: 2, ServicesGone: 1, Changed: 1, Unstable: 1}, c)
	assert.Equal(t, 7, c.Total())
	assert.Equal(t, c, FromKinds(map[model.ChangeKind]int{model.ChangeNew: 2, model.ChangeGone: 1,
		model.ChangeChanged: 1, model.ChangeHostUp: 1, model.ChangeHostDown: 1, model.ChangeUnstable: 1}))
}

func TestHeadline(t *testing.T) {
	title, sub := Headline(Counts{NewServices: 3, HostsGone: 1, Changed: 2}, 0)
	assert.Equal(t, "Since the last scan: 3 new exposures, 1 host gone, 2 services changed.", title)
	assert.Equal(t, "Nothing needs urgent attention.", sub)

	title, sub = Headline(Counts{NewServices: 1, Changed: 1}, 1)
	assert.Equal(t, "Since the last scan: 1 new exposure, 1 service changed.", title)
	assert.Equal(t, "1 service needs attention first.", sub)

	title, sub = Headline(Counts{NewHosts: 4}, 2)
	assert.Equal(t, "No changes since the last scan.", title)
	assert.Equal(t, "2 services need attention first.", sub)
}

func TestStrongest(t *testing.T) {
	i, sev := Strongest(nil)
	assert.Equal(t, -1, i)
	assert.Equal(t, model.SevInfo, sev)

	dets := []model.Detection{
		{Name: "Nginx", Category: "server"},
		{Name: "Admin", Category: "admin-panel"},
		{Name: "Staging", Category: "staging"},
		{Name: "Custom", Category: "other", Evidence: map[string]string{"severity": "high"}},
	}
	i, sev = Strongest(dets)
	assert.Equal(t, 3, i)
	assert.Equal(t, model.SevHigh, sev)

	i, sev = Strongest(dets[:3]) // ties keep the first
	assert.Equal(t, 1, i)
	assert.Equal(t, model.SevMedium, sev)
}

func TestRank(t *testing.T) {
	plain := store.ExportService{ServiceObs: model.ServiceObs{Key: key("10.0.0.1", 22), Banner: "ssh"}}
	db := store.ExportService{ServiceObs: model.ServiceObs{Key: key("10.0.0.2", 6379), Banner: "redis"}}
	admin := store.ExportService{ServiceObs: model.ServiceObs{Key: key("10.0.0.3", 8080), Banner: "http"},
		Detections: []model.Detection{{Name: "Tomcat Manager", Category: "admin-panel", Confidence: 100}}}
	fp := admin
	fp.Key = key("10.0.0.4", 8080)
	cs := []model.Change{{Kind: model.ChangeNew, Key: db.Key}, {Kind: model.ChangeChanged, Key: db.Key}}

	ranked := Rank([]store.ExportService{plain, db, admin, fp}, ChangeKinds(cs),
		map[netip.Addr]bool{netip.MustParseAddr("10.0.0.2"): true},
		map[model.AssetKey]store.Annotation{fp.Key: {FalsePositive: true}})

	assert.Len(t, 4, ranked)
	assert.Equal(t, db.Key, ranked[0].Service.Key)
	assert.Equal(t, 20+15+5+5, ranked[0].Score) // database, new, changed, unstable host
	assert.Equal(t, []string{"new", "changed"}, ranked[0].Kinds)
	assert.Equal(t, admin.Key, ranked[1].Service.Key)
	assert.Equal(t, 45, ranked[1].Score)
	// Equal scores keep the input order.
	assert.Equal(t, plain.Key, ranked[2].Service.Key)
	assert.Equal(t, fp.Key, ranked[3].Service.Key)
	assert.Equal(t, 0, ranked[3].Score)
}
