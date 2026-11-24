package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"os"
	"sort"

	"github.com/jackc/pgx/v5"

	"github.com/chrobson/ramparteye/internal/store"
)

const verifyUsage = "usage: ramparteye verify <expected.json> [--run ID] [--min 0.9]"

type verifyArgs struct {
	file  string
	runID int64
	min   float64
}

// parseVerifyArgs accepts the expectation file before or after the flags.
func parseVerifyArgs(args []string) (verifyArgs, error) {
	fs := flags("verify")
	var runID runIDFlag
	fs.Var(&runID, "run", "run id (default: the latest finished run)")
	minScore := fs.Float64("min", 0.9, "minimum precision/recall for a pass")
	var a verifyArgs
	if len(args) > 0 && len(args[0]) > 0 && args[0][0] != '-' {
		a.file, args = args[0], args[1:]
	}
	if err := parseFlags(fs, args, verifyUsage); err != nil {
		return a, err
	}
	rest := fs.Args()
	if a.file == "" && len(rest) > 0 {
		a.file, rest = rest[0], rest[1:]
	}
	if a.file == "" || len(rest) > 0 {
		return a, usageError(verifyUsage)
	}
	if *minScore < 0 || *minScore > 1 {
		return a, usageError("--min must be between 0 and 1\n" + verifyUsage)
	}
	a.runID, a.min = int64(runID), *minScore
	return a, nil
}

// cmdVerify compares a run with a lab expectation file (lab/expected/runN.json)
// and prints precision and recall of hosts, services, detections and
// changes. It exits non-zero when a score is below --min.
func cmdVerify(e *env, args []string) int {
	a, err := parseVerifyArgs(args)
	if err != nil {
		return e.fail("verify", err)
	}
	exp, err := loadExpected(a.file)
	if err != nil {
		return e.fail("verify", err)
	}
	cfg, code := e.config()
	if code != exitOK {
		return code
	}
	pool, st, err := openStore(e.ctx, cfg)
	if err != nil {
		return e.fail("verify", err)
	}
	defer pool.Close()
	runID := a.runID
	if runID == 0 {
		if runID, err = st.LatestDoneRun(e.ctx); err != nil {
			return e.fail("verify", err)
		}
		if runID == 0 {
			return e.fail("verify", errors.New("no finished run to verify"))
		}
	}
	obs, err := loadObserved(e.ctx, pool, runID)
	if err != nil {
		return e.fail("verify", err)
	}
	rep := evaluate(exp, a.file, obs, a.min)
	enc := json.NewEncoder(e.stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(rep); err != nil {
		return e.fail("verify", err)
	}
	if !rep.Pass {
		fmt.Fprintf(e.stderr, "ramparteye: verify: failed: %v\n", rep.Failures)
		return exitFail
	}
	return exitOK
}

// expected is the lab ground truth (lab/expected/runN.json).
type expected struct {
	Run     string `json:"run"`
	Network string `json:"network"`
	Infra   []struct {
		IP string `json:"ip"`
	} `json:"infra"`
	Hosts []struct {
		IP       string `json:"ip"`
		Name     string `json:"name"`
		Services []struct {
			Port       int      `json:"port"`
			Proto      string   `json:"proto"`
			InTop1000  bool     `json:"in_top1000"`
			Detections []string `json:"detections"`
		} `json:"services"`
	} `json:"hosts"`
	Changes []struct {
		Kind      string `json:"kind"`
		IP        string `json:"ip"`
		Port      int    `json:"port"`
		Proto     string `json:"proto"`
		InTop1000 *bool  `json:"in_top1000"`
	} `json:"changes_from_prev"`
}

func loadExpected(path string) (expected, error) {
	var e expected
	b, err := os.ReadFile(path)
	if err != nil {
		return e, err
	}
	if err := json.Unmarshal(b, &e); err != nil {
		return e, fmt.Errorf("%s: %w", path, err)
	}
	return e, nil
}

// detectionAliases maps the detection names of lab/expected to the
// signature ids that satisfy them.
var detectionAliases = map[string][]string{
	"staging-vhost":   {"staging-env"},
	"login-panel":     {"login-page"},
	"mqtt-anonymous":  {"mosquitto-mqtt"},
	"ip-camera":       {"iot-webui", "ip-camera"},
	"router-login":    {"iot-webui", "router-login"},
	"tomcat":          {"tomcat"},
	"tomcat-manager":  {"tomcat-manager"},
	"haproxy-stats":   {"haproxy-stats"},
	"nats-monitoring": {"nats-monitoring"},
}

func aliases(name string) []string {
	if a, ok := detectionAliases[name]; ok {
		return a
	}
	return []string{name}
}

// metric is a precision/recall score over a set of items.
type metric struct {
	Expected   int      `json:"expected"`
	Found      int      `json:"found"`
	TP         int      `json:"tp"`
	FP         int      `json:"fp"`
	FN         int      `json:"fn"`
	Precision  float64  `json:"precision"`
	Recall     float64  `json:"recall"`
	Missing    []string `json:"missing,omitempty"`
	Unexpected []string `json:"unexpected,omitempty"`
	// RecallTop1000 ignores expected items on ports outside nmap's top 1000
	// (the reference scan cannot see them).
	RecallTop1000 *float64 `json:"recall_top1000,omitempty"`
}

// verifyReport is the output of `ramparteye verify`.
type verifyReport struct {
	RunID      int64    `json:"run_id"`
	PrevRunID  int64    `json:"prev_run_id,omitempty"`
	Expected   string   `json:"expected"`
	DurationMS *int64   `json:"duration_ms,omitempty"`
	Hosts      metric   `json:"hosts"`
	Services   metric   `json:"services"`
	Detections metric   `json:"detections"`
	Changes    metric   `json:"changes"`
	MinScore   float64  `json:"min_score"`
	Pass       bool     `json:"pass"`
	Failures   []string `json:"failures,omitempty"`
}

func round3(f float64) float64 { return math.Round(f*1000) / 1000 }

func score(exp, got, top map[string]bool) metric {
	m := metric{Expected: len(exp), Found: len(got)}
	for k := range got {
		if exp[k] {
			m.TP++
		} else {
			m.FP++
			m.Unexpected = append(m.Unexpected, k)
		}
	}
	for k := range exp {
		if !got[k] {
			m.FN++
			m.Missing = append(m.Missing, k)
		}
	}
	sort.Strings(m.Missing)
	sort.Strings(m.Unexpected)
	m.Precision, m.Recall = 1, 1
	if m.Found > 0 {
		m.Precision = round3(float64(m.TP) / float64(m.Found))
	}
	if m.Expected > 0 {
		m.Recall = round3(float64(m.TP) / float64(m.Expected))
	}
	if top != nil {
		n, hit := 0, 0
		for k := range exp {
			if !top[k] {
				continue
			}
			n++
			if got[k] {
				hit++
			}
		}
		r := 1.0
		if n > 0 {
			r = round3(float64(hit) / float64(n))
		}
		m.RecallTop1000 = &r
	}
	return m
}

// observed is what a run stored, as compared by verify.
type observed struct {
	RunID      int64
	PrevRunID  int64
	DurationMS *int64
	Hosts      []string // addresses seen up
	Services   []obsService
	Detections []obsDetection
	Changes    []obsChange
}

type obsService struct {
	IP    string
	Port  int
	Proto string
}

type obsDetection struct {
	IP          string
	Port        int
	SignatureID string
}

type obsChange struct {
	Kind  string
	IP    string
	Port  int
	Proto string
}

func serviceKey(ip string, port int, proto string) string {
	return fmt.Sprintf("%s:%d/%s", ip, port, proto)
}

func detectionKey(ip string, port int, name string) string {
	return fmt.Sprintf("%s:%d:%s", ip, port, name)
}

func changeKey(kind, ip string, port int, proto string) string {
	if port == 0 {
		return kind + " " + ip
	}
	return fmt.Sprintf("%s %s:%d/%s", kind, ip, port, proto)
}

// evaluate scores obs against e. Addresses of the lab infrastructure and
// outside the lab network are ignored; detections are scored only for
// signatures in the lab vocabulary. The pass criteria are host precision
// and recall, service precision and top-1000 recall and, when the run has a
// predecessor and the file lists changes, change top-1000 recall.
func evaluate(e expected, path string, obs observed, minScore float64) verifyReport {
	rep := verifyReport{RunID: obs.RunID, PrevRunID: obs.PrevRunID, Expected: path,
		DurationMS: obs.DurationMS, MinScore: minScore}

	var network netip.Prefix
	if e.Network != "" {
		network, _ = netip.ParsePrefix(e.Network)
	}
	infra := map[string]bool{}
	for _, i := range e.Infra {
		infra[i.IP] = true
	}
	inScope := func(ip string) bool {
		if infra[ip] {
			return false
		}
		if !network.IsValid() {
			return true
		}
		a, err := netip.ParseAddr(ip)
		return err == nil && network.Contains(a)
	}

	// Ground truth.
	expHosts, expSvcs, topSvcs := map[string]bool{}, map[string]bool{}, map[string]bool{}
	expDets, topDets := map[string]bool{}, map[string]bool{}
	vocab := map[string]string{} // signature id -> expected name
	for _, h := range e.Hosts {
		expHosts[h.IP] = true
		for _, s := range h.Services {
			k := serviceKey(h.IP, s.Port, s.Proto)
			expSvcs[k] = true
			if s.InTop1000 {
				topSvcs[k] = true
			}
			for _, d := range s.Detections {
				dk := detectionKey(h.IP, s.Port, d)
				expDets[dk] = true
				if s.InTop1000 {
					topDets[dk] = true
				}
				for _, a := range aliases(d) {
					vocab[a] = d
				}
			}
		}
	}
	// Signatures named in the expectations of any run are scored even when
	// absent from this run's ground truth.
	for name := range detectionAliases {
		for _, a := range aliases(name) {
			if _, ok := vocab[a]; !ok {
				vocab[a] = name
			}
		}
	}
	expChanges, topChanges := map[string]bool{}, map[string]bool{}
	for _, c := range e.Changes {
		k := changeKey(c.Kind, c.IP, c.Port, c.Proto)
		expChanges[k] = true
		if c.InTop1000 == nil || *c.InTop1000 {
			topChanges[k] = true
		}
	}

	// Observed.
	gotHosts := map[string]bool{}
	for _, ip := range obs.Hosts {
		if inScope(ip) {
			gotHosts[ip] = true
		}
	}
	gotSvcs := map[string]bool{}
	for _, s := range obs.Services {
		if inScope(s.IP) {
			gotSvcs[serviceKey(s.IP, s.Port, s.Proto)] = true
		}
	}
	gotDets := map[string]bool{}
	for _, d := range obs.Detections {
		name, ok := vocab[d.SignatureID]
		if !ok || !inScope(d.IP) {
			continue // signatures outside the lab vocabulary are not scored
		}
		// One signature may satisfy several expected names (iot-webui).
		matched := false
		for en := range detectionAliases {
			for _, a := range aliases(en) {
				if k := detectionKey(d.IP, d.Port, en); a == d.SignatureID && expDets[k] {
					gotDets[k] = true
					matched = true
				}
			}
		}
		if !matched {
			gotDets[detectionKey(d.IP, d.Port, name)] = true
		}
	}
	gotChanges := map[string]bool{}
	for _, c := range obs.Changes {
		if inScope(c.IP) {
			gotChanges[changeKey(c.Kind, c.IP, c.Port, c.Proto)] = true
		}
	}

	rep.Hosts = score(expHosts, gotHosts, nil)
	rep.Services = score(expSvcs, gotSvcs, topSvcs)
	rep.Detections = score(expDets, gotDets, topDets)
	rep.Changes = score(expChanges, gotChanges, topChanges)

	check := func(name string, v float64) {
		if v < minScore {
			rep.Failures = append(rep.Failures, fmt.Sprintf("%s = %.3f < %.2f", name, v, minScore))
		}
	}
	check("hosts.precision", rep.Hosts.Precision)
	check("hosts.recall", rep.Hosts.Recall)
	check("services.precision", rep.Services.Precision)
	check("services.recall_top1000", *rep.Services.RecallTop1000)
	if rep.PrevRunID != 0 && len(expChanges) > 0 {
		check("changes.recall_top1000", *rep.Changes.RecallTop1000)
	}
	rep.Pass = len(rep.Failures) == 0
	return rep
}

// loadObserved reads what run runID stored.
func loadObserved(ctx context.Context, db store.DBTX, runID int64) (observed, error) {
	obs := observed{RunID: runID}
	err := db.QueryRow(ctx, `SELECT r.duration_ms, coalesce(d.prev_run_id, 0)
		FROM scan_runs r LEFT JOIN diff_runs d ON d.run_id = r.id WHERE r.id = $1`, runID).
		Scan(&obs.DurationMS, &obs.PrevRunID)
	if err != nil {
		return obs, fmt.Errorf("run %d: %w", runID, err)
	}
	if obs.Hosts, err = queryAll(ctx, db, pgx.RowTo[string],
		`SELECT host(ip) FROM host_obs WHERE run_id = $1 AND up`, runID); err != nil {
		return obs, err
	}
	if obs.Services, err = queryAll(ctx, db, pgx.RowToStructByPos[obsService],
		`SELECT host(ip), port, proto FROM services WHERE run_id = $1`, runID); err != nil {
		return obs, err
	}
	if obs.Detections, err = queryAll(ctx, db, pgx.RowToStructByPos[obsDetection],
		`SELECT host(s.ip), s.port, d.signature_id
		FROM detections d JOIN services s ON s.id = d.service_id WHERE s.run_id = $1`, runID); err != nil {
		return obs, err
	}
	obs.Changes, err = queryAll(ctx, db, pgx.RowToStructByPos[obsChange],
		`SELECT kind, host(ip), port, proto FROM changes WHERE run_id = $1`, runID)
	return obs, err
}

func queryAll[T any](ctx context.Context, db store.DBTX, row pgx.RowToFunc[T], sql string, args ...any) ([]T, error) {
	rows, err := db.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, row)
}
