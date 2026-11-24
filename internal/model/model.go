// Package model holds the shared domain types.
package model

import (
	"net/netip"
	"time"
)

// AssetKey is the natural key of a service across scan runs. Annotations,
// diff and DefectDojo unique IDs are all derived from it.
type AssetKey struct {
	IP    netip.Addr
	Port  uint16 // 0 = host-level
	Proto string // "tcp" | "udp" | ""
	VHost string // "" unless a virtual host was probed
}

// TargetKind is the kind of an imported target.
type TargetKind string

const (
	TargetIP     TargetKind = "ip"
	TargetCIDR   TargetKind = "cidr"
	TargetDomain TargetKind = "domain"
	TargetRange  TargetKind = "range"
)

// Target is one imported scan target.
type Target struct {
	ID    int64
	Kind  TargetKind
	Value string
	Tags  []string
}

// HostObs is a single host observation in one run.
type HostObs struct {
	RunID    int64
	IP       netip.Addr
	Hostname string
	Up       bool
}

// ServiceObs is one open service observed in one run.
type ServiceObs struct {
	ID        int64
	RunID     int64
	Key       AssetKey
	Product   string
	Version   string
	ExtraInfo string
	CPE       string
	Banner    string
}

// Endpoint is an HTTP(S) endpoint to probe.
type Endpoint struct {
	ServiceID int64
	Key       AssetKey
	Scheme    string // "http" | "https"
}

// Redirect is one hop of a redirect chain.
type Redirect struct {
	URL    string `json:"url"`
	Status int    `json:"status"`
}

// TLSInfo describes the leaf certificate presented by a TLS service.
type TLSInfo struct {
	Subject    string    `json:"subject"`
	Issuer     string    `json:"issuer"`
	SANs       []string  `json:"sans"`
	NotBefore  time.Time `json:"not_before"`
	NotAfter   time.Time `json:"not_after"`
	Expired    bool      `json:"expired"`
	SelfSigned bool      `json:"self_signed"`
	Mismatch   bool      `json:"hostname_mismatch"`
	Version    string    `json:"version"`
}

// Cookie is a Set-Cookie observation (values are not stored).
type Cookie struct {
	Name     string `json:"name"`
	Secure   bool   `json:"secure"`
	HTTPOnly bool   `json:"http_only"`
	SameSite string `json:"same_site"`
}

// HTTPObs is the result of probing an HTTP(S) endpoint.
type HTTPObs struct {
	ServiceID   int64
	URL         string
	Status      int
	Title       string
	Headers     map[string][]string
	Cookies     []Cookie
	Redirects   []Redirect
	TLS         *TLSInfo
	FaviconMMH3 *int32
	BodySHA256  string
	// ResponseMS is the duration of the first request to the service in
	// milliseconds (connect, TLS, headers and body); 0 = not measured.
	ResponseMS int
	Body       []byte // capped, in memory only for signature matching; never persisted
}

// Detection is a signature match on a service.
type Detection struct {
	ServiceID   int64
	SignatureID string
	Name        string
	Category    string // cms|framework|server|iot|admin-panel|staging|other
	Confidence  int    // 0-100
	Evidence    map[string]string
	// Meta is the signature's CWE/ATT&CK/remediation metadata. It is not
	// stored with the detection: readers attach it from the current
	// signature set (nil when the signature has none or was removed).
	Meta *SignatureMeta `json:"-"`
}

// SignatureMeta is the optional classification a signature carries.
type SignatureMeta struct {
	CWE         []int    // CWE ids, most specific first
	Attack      []string // MITRE ATT&CK technique ids (T1190, T1078.001)
	Remediation string   // one-sentence fix, shown in the UI and exported as mitigation
	References  []string // http(s) URLs
}

// Empty reports whether m carries no metadata.
func (m *SignatureMeta) Empty() bool {
	return m == nil || (len(m.CWE) == 0 && len(m.Attack) == 0 && m.Remediation == "" && len(m.References) == 0)
}

// AttachMeta sets Detection.Meta from a map keyed by signature id.
func AttachMeta(dets []Detection, metas map[string]SignatureMeta) {
	for i := range dets {
		if m, ok := metas[dets[i].SignatureID]; ok && !m.Empty() {
			m := m
			dets[i].Meta = &m
		}
	}
}

// ChangeKind classifies a difference between two runs.
type ChangeKind string

const (
	ChangeNew      ChangeKind = "new"
	ChangeGone     ChangeKind = "gone"
	ChangeChanged  ChangeKind = "changed"
	ChangeHostUp   ChangeKind = "host_up"
	ChangeHostDown ChangeKind = "host_down"
	ChangeUnstable ChangeKind = "unstable"
)

// Change is one difference between a run and its predecessor.
type Change struct {
	RunID     int64
	PrevRunID int64
	Kind      ChangeKind
	Key       AssetKey
	Field     string
	Old       string
	New       string
}

// HostStateKind is the lifecycle state of a host across runs.
type HostStateKind string

const (
	HostUp       HostStateKind = "up"
	HostDown     HostStateKind = "down"
	HostInactive HostStateKind = "inactive"
	HostUnstable HostStateKind = "unstable"
)

// Flip is one up/down observation used for instability detection.
type Flip struct {
	RunID int64 `json:"run"`
	Up    bool  `json:"up"`
}

// HostState is the cross-run state of a host.
type HostState struct {
	IP        netip.Addr
	State     HostStateKind
	Misses    int
	Flips     []Flip
	FirstSeen time.Time
	LastSeen  time.Time
}

// Severity values accepted by DefectDojo.
type Severity string

const (
	SevInfo     Severity = "Info"
	SevLow      Severity = "Low"
	SevMedium   Severity = "Medium"
	SevHigh     Severity = "High"
	SevCritical Severity = "Critical"
)

// Finding is the exchange unit for DefectDojo Generic Findings import/export.
type Finding struct {
	Title            string
	Severity         Severity
	Description      string // stable identity only: it is part of the DefectDojo hash
	Observed         string // volatile observed data (steps_to_reproduce), not hashed
	Date             time.Time
	UniqueIDFromTool string // rampart:svc:<ip>:<port>/<proto> | rampart:sig:<ip>:<port>:<sig_id>
	VulnIDFromTool   string // signature id, empty for plain services
	Endpoints        []AssetKey
	Tags             []string
	CWE              int    // first CWE of the signature, 0 = none
	Mitigation       string // signature remediation
	References       string // newline-separated URLs
}

// NewUser is an account to create. Role names a role (Admin, Operator,
// Analyst, Viewer or a custom one); PasswordHash is already hashed.
type NewUser struct {
	Login              string
	PasswordHash       string
	Role               string
	MustChangePassword bool
}
