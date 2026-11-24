package diff

import (
	"testing"
	"time"

	"github.com/ctx42/testing/pkg/assert"

	"github.com/chrobson/ramparteye/internal/model"
)

func flips(ups ...bool) []model.Flip {
	out := make([]model.Flip, len(ups))
	for i, u := range ups {
		out[i] = model.Flip{RunID: int64(i + 1), Up: u}
	}
	return out
}

func TestDiffNewGoneChanged(t *testing.T) {
	prev := []model.ServiceObs{
		svc(1, "10.0.0.1", 22, "OpenSSH", "7.4"),
		svc(1, "10.0.0.1", 23, "BusyBox telnetd", ""),
	}
	curr := []model.ServiceObs{
		svc(2, "10.0.0.1", 22, "OpenSSH", "8.9p1"),
		svc(2, "10.0.0.1", 8080, "Werkzeug httpd", "3.0.1"),
	}

	have := Diff(prev, curr, nil, testCfg)

	assert.Equal(t, []string{
		`changed 10.0.0.1:22/tcp version "7.4"->"8.9p1"`,
		`gone 10.0.0.1:23/tcp "BusyBox telnetd"->""`,
		`new 10.0.0.1:8080/tcp ""->"Werkzeug httpd 3.0.1"`,
	}, fmtChanges(have))
	for _, c := range have {
		assert.Equal(t, int64(2), c.RunID)
		assert.Equal(t, int64(1), c.PrevRunID)
	}
}

func TestCompareServices(t *testing.T) {
	base := svc(1, "10.0.0.1", 22, "OpenSSH", "7.4")
	k := base.Key

	t.Run("identical and empty", func(t *testing.T) {
		assert.Len(t, 0, CompareServices([]model.ServiceObs{base}, []model.ServiceObs{base}))
		assert.Len(t, 0, CompareServices(nil, nil))
	})
	t.Run("one change per differing field", func(t *testing.T) {
		a := model.ServiceObs{Key: k, Product: "a", Version: "1", ExtraInfo: "x", CPE: "cpe:/a", Banner: "b1"}
		b := model.ServiceObs{Key: k, Product: "b", Version: "2", ExtraInfo: "y", CPE: "cpe:/b", Banner: "b2"}

		have := CompareServices([]model.ServiceObs{a}, []model.ServiceObs{b})
		SortChanges(have)

		assert.Equal(t, []string{
			`changed 10.0.0.1:22/tcp product "a"->"b"`,
			`changed 10.0.0.1:22/tcp version "1"->"2"`,
			`changed 10.0.0.1:22/tcp extrainfo "x"->"y"`,
			`changed 10.0.0.1:22/tcp cpe "cpe:/a"->"cpe:/b"`,
			`changed 10.0.0.1:22/tcp banner "b1"->"b2"`,
		}, fmtChanges(have))
	})
	t.Run("vhost and proto are part of the key", func(t *testing.T) {
		mk := func(proto, vhost string) model.ServiceObs {
			return model.ServiceObs{Key: model.AssetKey{IP: ip("10.0.0.1"), Port: 80, Proto: proto, VHost: vhost}}
		}

		have := CompareServices(
			[]model.ServiceObs{mk("tcp", "a.example")},
			[]model.ServiceObs{mk("tcp", "b.example"), mk("udp", "a.example")},
		)
		SortChanges(have)

		assert.Equal(t, []string{
			`gone 10.0.0.1:80/tcp (a.example)`,
			`new 10.0.0.1:80/tcp (b.example)`,
			`new 10.0.0.1:80/udp (a.example)`,
		}, fmtChanges(have))
	})
	t.Run("ipv4-mapped matches plain ipv4", func(t *testing.T) {
		p := model.ServiceObs{Key: model.AssetKey{IP: ip("::ffff:10.0.0.1"), Port: 22, Proto: "tcp"}}
		c := model.ServiceObs{Key: model.AssetKey{IP: ip("10.0.0.1"), Port: 22, Proto: "tcp"}}

		assert.Len(t, 0, CompareServices([]model.ServiceObs{p}, []model.ServiceObs{c}))
	})
}

func TestClassify(t *testing.T) {
	tests := []struct {
		name   string
		flips  []model.Flip
		misses int
		cfg    Config
		want   model.HostStateKind
	}{
		{"no history", nil, 0, testCfg, model.HostDown},
		{"always up", flips(true, true, true), 0, testCfg, model.HostUp},
		{"one miss", flips(true, false), 1, testCfg, model.HostDown},
		{"one flip back up", flips(false, true), 0, testCfg, model.HostUp},
		{"two flips unstable", flips(true, false, true), 0, testCfg, model.HostUnstable},
		{"unstable while down", flips(true, false, true, false), 1, testCfg, model.HostUnstable},
		{"inactive beats unstable", flips(true, false, true, false, false, false), 3, testCfg, model.HostInactive},
		{"misses below threshold", flips(true, true, false, false), 2, testCfg, model.HostDown},
		{"flips outside window forgotten", flips(true, false, true, true, true, true, true), 0, testCfg, model.HostUp},
		{"higher flip threshold", flips(true, false, true), 0, Config{InactiveAfterMisses: 3, UnstableIfFlips: 3, Window: 5}, model.HostUp},
		{"zero thresholds disable rules", flips(true, false, true, false), 9, Config{}, model.HostDown},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, Classify(tt.flips, tt.misses, tt.cfg))
		})
	}
}

func TestHostDownAfterMiss(t *testing.T) {
	t0 := time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC)
	a := ip("10.0.0.9")
	up := Step(nil, a, true, 1, t0, testCfg)

	down := Step(&up, a, false, 2, t0.Add(time.Hour), testCfg)

	assert.Equal(t, model.HostDown, down.State)
	assert.Equal(t, 1, down.Misses)
	assert.Equal(t, t0, down.LastSeen)
	assert.Equal(t, []string{`host_down 10.0.0.9 "up"->"down"`},
		fmtChanges(HostChanges([]model.HostState{down}, 2, testCfg)))
}

func TestInactiveAfterThreeMisses(t *testing.T) {
	t0 := time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC)
	a := ip("10.0.0.9")
	h := Step(nil, a, true, 1, t0, testCfg)

	for i, want := range []model.HostStateKind{model.HostDown, model.HostDown, model.HostInactive} {
		h = Step(&h, a, false, int64(i+2), t0.Add(time.Duration(i+1)*time.Hour), testCfg)
		assert.Equal(t, want, h.State)
		assert.Equal(t, i+1, h.Misses)
	}

	h = Step(&h, a, true, 5, t0.Add(5*time.Hour), testCfg)
	assert.Equal(t, 0, h.Misses)
	assert.Equal(t, t0.Add(5*time.Hour), h.LastSeen)
}

func TestUnstableTwoFlipsInFive(t *testing.T) {
	t0 := time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC)
	a := ip("10.0.0.9")
	h := Step(nil, a, true, 1, t0, testCfg)
	h = Step(&h, a, false, 2, t0, testCfg)
	assert.Equal(t, model.HostDown, h.State)

	h = Step(&h, a, true, 3, t0, testCfg)

	assert.Equal(t, model.HostUnstable, h.State)
	assert.Equal(t, []string{
		`host_up 10.0.0.9 ""->"up"`,
		`unstable 10.0.0.9 flips ""->"2"`,
	}, fmtChanges(HostChanges([]model.HostState{h}, 3, testCfg)))
}

func TestStepIdempotentTrimmedAndImmutable(t *testing.T) {
	t0 := time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC)
	a := ip("10.0.0.9")
	h := Step(nil, a, true, 1, t0, testCfg)

	again := Step(&h, a, false, 1, t0.Add(time.Hour), testCfg)
	assert.Equal(t, h, again)

	before := h
	snapshot := append([]model.Flip(nil), before.Flips...)
	_ = Step(&before, a, false, 2, t0, testCfg)
	assert.Equal(t, snapshot, before.Flips)

	for r := int64(2); r < 20; r++ {
		h = Step(&h, a, true, r, t0, testCfg)
	}
	assert.Len(t, testCfg.Window, h.Flips)
	assert.Equal(t, int64(19), h.Flips[len(h.Flips)-1].RunID)
}

func TestAdvance(t *testing.T) {
	t0 := time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC)
	known := []model.HostState{
		Step(nil, ip("10.0.0.1"), true, 1, t0, testCfg),
		Step(nil, ip("10.0.0.2"), true, 1, t0, testCfg),
		Step(nil, ip("10.0.0.3"), true, 1, t0, testCfg),
	}
	obs := []model.HostObs{
		{RunID: 2, IP: ip("10.0.0.1"), Up: true},
		{RunID: 2, IP: ip("10.0.0.2"), Up: false},
		{RunID: 2, IP: ip("10.0.0.7"), Up: false}, // never seen up: not tracked
	}
	curr := []model.ServiceObs{svc(2, "10.0.0.8", 80, "nginx", "")} // service implies up

	have := AdvanceAt(known, obs, curr, 2, t0, testCfg)

	var got []string
	for _, h := range have {
		got = append(got, h.IP.String()+"="+string(h.State)+"/"+string(rune('0'+h.Misses)))
	}
	assert.Equal(t, []string{"10.0.0.1=up/0", "10.0.0.2=down/1", "10.0.0.3=down/1", "10.0.0.8=up/0"}, got)
}

func TestHostChangesOnlyForCurrentRun(t *testing.T) {
	t0 := time.Now()
	up1 := Step(nil, ip("10.0.0.1"), true, 1, t0, testCfg)
	stays := Step(&up1, ip("10.0.0.1"), true, 2, t0, testCfg)

	assert.Len(t, 1, HostChanges([]model.HostState{up1}, 1, testCfg))
	assert.Len(t, 0, HostChanges([]model.HostState{stays}, 2, testCfg))
	assert.Len(t, 0, HostChanges([]model.HostState{up1}, 2, testCfg))
}

func TestDiffThreeRunScenario(t *testing.T) {
	t0 := time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC)
	type run struct {
		id       int64
		hosts    []string
		services []model.ServiceObs
	}
	runs := []run{
		{1, []string{"10.20.0.10", "10.20.24.30", "10.20.60.120"}, []model.ServiceObs{
			svc(1, "10.20.0.10", 80, "nginx", "1.27.3"),
			svc(1, "10.20.24.30", 23, "BusyBox telnetd", ""),
			svc(1, "10.20.24.30", 22, "OpenSSH", "7.4"),
			svc(1, "10.20.60.120", 80, "busybox httpd", ""),
		}},
		{2, []string{"10.20.0.10", "10.20.24.30"}, []model.ServiceObs{
			svc(2, "10.20.0.10", 80, "nginx", "1.27.3"),
			svc(2, "10.20.0.10", 8080, "Werkzeug httpd", "3.0.1"),
			svc(2, "10.20.24.30", 22, "OpenSSH", "8.9p1"),
		}},
		{3, []string{"10.20.0.10", "10.20.24.30", "10.20.60.120"}, []model.ServiceObs{
			svc(3, "10.20.0.10", 80, "nginx", "1.27.3"),
			svc(3, "10.20.0.10", 8080, "Werkzeug httpd", "3.0.1"),
			svc(3, "10.20.24.30", 22, "OpenSSH", "8.9p1"),
			svc(3, "10.20.60.120", 80, "busybox httpd", ""),
		}},
	}
	wantChanges := [][]string{
		{},
		{
			`new 10.20.0.10:8080/tcp ""->"Werkzeug httpd 3.0.1"`,
			`changed 10.20.24.30:22/tcp version "7.4"->"8.9p1"`,
			`gone 10.20.24.30:23/tcp "BusyBox telnetd"->""`,
			`host_down 10.20.60.120 "up"->"down"`,
			`gone 10.20.60.120:80/tcp "busybox httpd"->""`,
		},
		{
			`host_up 10.20.60.120 ""->"up"`,
			`unstable 10.20.60.120 flips ""->"2"`,
			`new 10.20.60.120:80/tcp ""->"busybox httpd"`,
		},
	}
	wantStates := []model.HostStateKind{model.HostUp, model.HostDown, model.HostUnstable}

	var known []model.HostState
	var prev []model.ServiceObs
	for i, r := range runs {
		var obs []model.HostObs
		for _, h := range r.hosts {
			obs = append(obs, model.HostObs{RunID: r.id, IP: ip(h), Up: true})
		}
		known = AdvanceAt(known, obs, r.services, r.id, t0.Add(time.Duration(i)*time.Hour), testCfg)
		var got []model.Change
		if i > 0 {
			got = Diff(prev, r.services, known, testCfg)
		}
		assert.Equal(t, wantChanges[i], fmtChanges(got))
		for _, h := range known {
			if h.IP == ip("10.20.60.120") {
				assert.Equal(t, wantStates[i], h.State)
			}
		}
		prev = r.services
	}

	keep := runs[2].services[:3]
	up := []model.HostObs{
		{RunID: 4, IP: ip("10.20.0.10"), Up: true}, {RunID: 4, IP: ip("10.20.24.30"), Up: true},
	}
	known = AdvanceAt(known, up, keep, 4, t0, testCfg)
	assert.Equal(t, []string{
		`host_down 10.20.60.120 "up"->"down"`,
		`unstable 10.20.60.120 flips ""->"3"`,
	}, fmtChanges(HostChanges(known, 4, testCfg)))
	for r := int64(5); r <= 6; r++ {
		known = AdvanceAt(known, nil, keep, r, t0, testCfg)
	}
	for _, h := range known {
		if h.IP == ip("10.20.60.120") {
			assert.Equal(t, model.HostInactive, h.State)
			assert.Equal(t, 3, h.Misses)
		}
	}
}

func TestDiffRunIDsFromHistory(t *testing.T) {
	h := Step(nil, ip("10.0.0.1"), true, 7, time.Now(), testCfg)
	h = Step(&h, ip("10.0.0.1"), false, 9, time.Now(), testCfg)

	have := Diff([]model.ServiceObs{svc(7, "10.0.0.1", 22, "OpenSSH", "")}, nil, []model.HostState{h}, testCfg)

	assert.Len(t, 2, have)
	for _, c := range have {
		assert.Equal(t, int64(9), c.RunID)
		assert.Equal(t, int64(7), c.PrevRunID)
	}
}

func TestDropUncarried(t *testing.T) {
	cs := []model.Change{
		{Kind: model.ChangeChanged, Field: "banner", Old: "x", New: ""},
		{Kind: model.ChangeChanged, Field: "version", Old: "1", New: "2"},
		{Kind: model.ChangeGone, Old: "x"},
	}

	have := DropUncarried(cs)

	assert.Len(t, 2, have)
	assert.Equal(t, "version", have[0].Field)
}

func TestServiceInstability(t *testing.T) {
	flap := model.AssetKey{IP: ip("127.0.0.1"), Port: 8787, Proto: "tcp"}
	once := model.AssetKey{IP: ip("127.0.0.1"), Port: 15432, Proto: "tcp"}
	hostFlap := model.AssetKey{IP: ip("10.20.60.120"), Port: 80, Proto: "tcp"}
	cs := []model.Change{
		{Kind: model.ChangeNew, Key: flap},
		{Kind: model.ChangeGone, Key: once},
		{Kind: model.ChangeUnstable, Key: model.AssetKey{IP: hostFlap.IP}},
		{Kind: model.ChangeNew, Key: hostFlap},
	}
	prior := map[model.AssetKey]int{flap: 1, hostFlap: 3}

	have := ServiceInstability(cs, prior, testCfg)

	assert.Len(t, 1, have)
	assert.Equal(t, flap, have[0].Key)
	assert.Equal(t, "2", have[0].New)
	assert.Equal(t, "flips", have[0].Field)
	assert.Nil(t, ServiceInstability(cs, prior, Config{}))
	assert.Equal(t, 3, PriorRuns(testCfg))
}
