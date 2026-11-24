// Package interest computes a transparent 0-100 interest score for a
// service: a deterministic sum of the rules below, built only from data the
// scan already stored (detections, nmap service, TLS facts, changes and the
// analyst annotation). It is a triage aid for "what to look at first", not a
// vulnerability assessment.
//
// Rule table (all points are additive, the total is capped at 100):
//
//	a) detection severity   highest of points(sev) x confidence/100:
//	                        Critical 60, High 45, Medium 25, Low 10, Info 0
//	b) category (once each) admin panel +20, staging +15, IoT +15, CMS +5
//	c) outdated version     +15 (any detection with evidence "outdated")
//	d) exposed service      only the highest class applies, matched by the
//	                        nmap service name first and the port second:
//	                        Docker API +40, telnet +30, database/cache +20,
//	                        remote desktop +20, FTP +15, message broker +10
//	e) TLS                  expired certificate +10, self-signed +5,
//	                        login form or admin panel over plain HTTP +10
//	f) change context       new service +15, changed +5, unstable host +5
//	g) analyst              false positive: score 0; analyst severity sets a
//	                        floor (Critical 90, High 70, Medium 40, Low 15);
//	                        Info caps the score at 10
//
// Priority is "high" from 60, "medium" from 30 and "low" below.
package interest

import (
	"fmt"
	"sort"
	"strings"
)

// Detection is the part of a signature match the score uses. Signature is
// the signature id; Severity is the effective severity; Outdated is the
// "outdated" evidence of the detection ("" when the version is current).
type Detection struct {
	Signature, Name, Category, Severity string
	Confidence                          int
	Outdated                            string
}

// Input is everything known about one service. Service is the nmap service
// name.
type Input struct {
	Port                      int
	Proto, Service, Product   string
	Scheme                    string
	Detections                []Detection
	TLSExpired, TLSSelfSigned bool
	ChangeKinds               []string
	HostUnstable              bool
	AnalystSeverity           string
	FalsePositive             bool
}

// Reason is one rule that contributed points.
type Reason struct {
	Rule   string
	Points int
}

// Result is the score with its priority and the contributing rules, highest
// first.
type Result struct {
	Score    int
	Priority string // low | medium | high
	Reasons  []Reason
}

var (
	severityPoints = map[string]int{"critical": 60, "high": 45, "medium": 25, "low": 10, "info": 0}
	categoryRules  = []struct {
		cat, rule string
		points    int
	}{
		{"admin-panel", "admin panel", 20},
		{"staging", "staging environment", 15},
		{"iot", "IoT device", 15},
		{"cms", "CMS", 5},
	}
	analystFloor = map[string]int{"critical": 90, "high": 70, "medium": 40, "low": 15}
)

const (
	pointsOutdated   = 15
	pointsTLSExpired = 10
	pointsSelfSigned = 5
	pointsLoginHTTP  = 10
	pointsNew        = 15
	pointsChanged    = 5
	pointsUnstable   = 5
	analystInfoCap   = 10
	maxScore         = 100
)

// ruleDatabase is the rule text of the database and cache class.
const ruleDatabase = "database or cache reachable from the network"

// serviceClass is an exposed service type that is interesting by itself.
type serviceClass struct {
	rule     string
	points   int
	services []string // nmap service names
	ports    []int    // fallback when nmap did not name the service
}

// serviceClasses is ordered by points, so the first match is the highest.
var serviceClasses = []serviceClass{
	{"Docker API without TLS", 40, []string{"docker"}, []int{2375}},
	{"telnet (unencrypted)", 30, []string{"telnet"}, []int{23}},
	{ruleDatabase, 20,
		[]string{"postgresql", "mysql", "ms-sql-s", "oracle", "oracle-tns", "mongodb", "mongod", "redis",
			"memcached", "memcache", "elasticsearch", "couchdb", "cassandra"},
		[]int{5432, 3306, 1433, 1521, 27017, 6379, 11211, 9200}},
	{"remote desktop", 20, []string{"ms-wbt-server", "vnc"}, []int{3389, 5900}},
	{"FTP", 15, []string{"ftp"}, []int{21}},
	{"message broker", 10, []string{"amqp", "mqtt"}, []int{5672, 1883}},
}

// matchClass returns the class of the service: by nmap service name first
// (so PostgreSQL on 15432 counts), then by well-known port (nmap reports
// Elasticsearch on 9200 as "http").
func matchClass(service string, port int) (serviceClass, bool) {
	svc := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(service)), "?")
	for _, c := range serviceClasses {
		for _, s := range c.services {
			if svc == s {
				return c, true
			}
		}
	}
	for _, c := range serviceClasses {
		for _, p := range c.ports {
			if port == p {
				return c, true
			}
		}
	}
	return serviceClass{}, false
}

// ExposedDatabase reports whether the nmap service name or port marks a
// database or cache, the class the score treats as "exposed database".
func ExposedDatabase(service string, port int) bool {
	c, ok := matchClass(service, port)
	return ok && c.rule == ruleDatabase
}

// Score evaluates the rules for one service.
func Score(in Input) Result {
	if in.FalsePositive {
		return Result{Priority: priority(0), Reasons: []Reason{{Rule: "marked as false positive"}}}
	}
	var reasons []Reason
	add := func(rule string, pts int) {
		if pts > 0 {
			reasons = append(reasons, Reason{Rule: rule, Points: pts})
		}
	}

	// a) highest detection severity weighted by confidence
	best, bestRule := 0, ""
	for _, d := range in.Detections {
		conf := min(max(d.Confidence, 0), 100)
		p := severityPoints[strings.ToLower(d.Severity)] * conf / 100
		if p > best {
			best, bestRule = p, fmt.Sprintf("detection %s: %s", d.Name, d.Severity)
		}
	}
	add(bestRule, best)

	// b) categories, once each
	for _, c := range categoryRules {
		for _, d := range in.Detections {
			if d.Category == c.cat {
				add(c.rule, c.points)
				break
			}
		}
	}

	// c) outdated version
	for _, d := range in.Detections {
		if d.Outdated != "" {
			add(fmt.Sprintf("outdated version (%s)", d.Outdated), pointsOutdated)
			break
		}
	}

	// d) exposed service class
	if c, ok := matchClass(in.Service, in.Port); ok {
		add(c.rule, c.points)
	}

	// e) TLS
	if in.TLSExpired {
		add("expired TLS certificate", pointsTLSExpired)
	}
	if in.TLSSelfSigned {
		add("self-signed TLS certificate", pointsSelfSigned)
	}
	if strings.EqualFold(in.Scheme, "http") {
		for _, d := range in.Detections {
			if d.Category == "admin-panel" || d.Signature == "login-page" {
				add("login without TLS", pointsLoginHTTP)
				break
			}
		}
	}

	// f) change context
	var isNew, changed, unstable bool
	for _, k := range in.ChangeKinds {
		switch k {
		case "new":
			isNew = true
		case "changed":
			changed = true
		case "unstable":
			unstable = true
		}
	}
	if isNew {
		add("new service in this run", pointsNew)
	}
	if changed {
		add("changed service", pointsChanged)
	}
	if unstable || in.HostUnstable {
		add("unstable host", pointsUnstable)
	}

	total := 0
	for _, r := range reasons {
		total += r.Points
	}
	total = min(total, maxScore)

	// g) analyst severity: floor, or cap for Info
	sev := strings.ToLower(strings.TrimSpace(in.AnalystSeverity))
	if floor, ok := analystFloor[sev]; ok && total < floor {
		reasons = append(reasons, Reason{Rule: "severity set by analyst", Points: floor - total})
		total = floor
	} else if sev == "info" && total > analystInfoCap {
		total = analystInfoCap
		reasons = append(reasons, Reason{Rule: "analyst: informational (score capped at 10)"})
	}

	sort.SliceStable(reasons, func(i, j int) bool { return reasons[i].Points > reasons[j].Points })
	return Result{Score: total, Priority: priority(total), Reasons: reasons}
}

func priority(score int) string {
	switch {
	case score >= 60:
		return "high"
	case score >= 30:
		return "medium"
	}
	return "low"
}
