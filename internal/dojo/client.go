package dojo

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	// MaxUploadBytes caps the findings file sent to DefectDojo.
	MaxUploadBytes = 32 << 20
	// MaxResponseBytes caps how much of a DefectDojo response is read.
	MaxResponseBytes = 4 << 20

	defaultTimeout = 120 * time.Second
	checkTimeout   = 20 * time.Second
	maxRedirects   = 3
	maxErrorBody   = 512
)

// reimportTimeout bounds Reimport when the http.Client has no Timeout.
var reimportTimeout = defaultTimeout

// Client is a minimal DefectDojo API v2 client. The API token is only ever
// sent to the host of the configured base URL.
type Client struct {
	base  string
	token string
	hc    *http.Client
}

// NewHTTPClient returns an http.Client with verified TLS. roots, when not
// nil, replaces the system CA pool (for a private DefectDojo CA); there is
// deliberately no way to disable verification.
func NewHTTPClient(roots *x509.CertPool, timeout time.Duration) *http.Client {
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}
	return &http.Client{Timeout: timeout, Transport: tr}
}

// NewClient returns a client for the DefectDojo at baseURL (no /api/v2
// suffix). hc may be nil for a verified-TLS client with a 120 s timeout. The
// given client is copied: its redirect policy is replaced so that redirects
// to another host (or from https to http) are refused, which keeps the token
// from leaving the configured server.
func NewClient(baseURL, token string, hc *http.Client) *Client {
	if hc == nil {
		hc = NewHTTPClient(nil, 0)
	}
	cp := *hc
	cp.CheckRedirect = checkRedirect
	return &Client{base: strings.TrimRight(strings.TrimSpace(baseURL), "/"), token: token, hc: &cp}
}

func checkRedirect(req *http.Request, via []*http.Request) error {
	if len(via) > maxRedirects {
		return errors.New("too many redirects")
	}
	first := via[0].URL
	if !strings.EqualFold(req.URL.Host, first.Host) {
		return fmt.Errorf("refusing redirect to another host %q", req.URL.Host)
	}
	if first.Scheme == "https" && req.URL.Scheme != "https" {
		return errors.New("refusing redirect from https to http")
	}
	return nil
}

// PushParams identify where findings land in DefectDojo. Product type,
// product and engagement are created on demand (auto_create_context).
type PushParams struct {
	ProductType      string // default "RampartEye"
	Product          string // default "RampartEye"
	Engagement       string // default "Continuous discovery"
	TestTitle        string // default "RampartEye Generic Findings"
	CloseOldFindings bool
}

func (p PushParams) withDefaults() PushParams {
	if p.ProductType == "" {
		p.ProductType = "RampartEye"
	}
	if p.Product == "" {
		p.Product = "RampartEye"
	}
	if p.Engagement == "" {
		p.Engagement = "Continuous discovery"
	}
	if p.TestTitle == "" {
		p.TestTitle = "RampartEye Generic Findings"
	}
	return p
}

// ImportResult is the subset of the reimport-scan response RampartEye
// records. Statistics is kept verbatim.
type ImportResult struct {
	TestID       int             `json:"test_id"`
	Test         int             `json:"test"`
	EngagementID int             `json:"engagement_id"`
	ProductID    int             `json:"product_id"`
	Statistics   json.RawMessage `json:"statistics,omitempty"`
}

// ID returns the test id regardless of which response field carried it.
func (r ImportResult) ID() int {
	if r.TestID != 0 {
		return r.TestID
	}
	return r.Test
}

// APIError is a non-2xx response from DefectDojo.
type APIError struct {
	Path   string
	Status int
	Body   string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("defectdojo %s: HTTP %d: %s", e.Path, e.Status, e.Body)
}

// CheckResult is the outcome of Check. Each flag implies the previous ones
// were reached, except ProductExists which needs a valid token.
type CheckResult struct {
	Reachable     bool
	TokenValid    bool
	CanImport     bool
	ProductExists bool
	// Version is best effort: the X-DefectDojo-Version response header when
	// the server sends it, otherwise empty.
	Version string
	User    string
}

// Check probes DefectDojo: server reachable, token accepted, the token's
// user may import, and the product exists. The error is non-nil only when
// the server could not be reached or answered unexpectedly; an invalid token
// is a result (TokenValid=false), not an error. A 403 is an error carrying
// the status (the server rejected the request for a reason other than the
// token) with Reachable=true.
func (c *Client) Check(ctx context.Context, product string) (CheckResult, error) {
	var res CheckResult
	ctx, cancel := context.WithTimeout(ctx, checkTimeout)
	defer cancel()

	body, hdr, err := c.get(ctx, "user_profile/")
	var apiErr *APIError
	switch {
	case errors.As(err, &apiErr) && apiErr.Status == http.StatusUnauthorized:
		res.Reachable = true
		res.Version = hdr.Get("X-DefectDojo-Version")
		return res, nil
	case errors.As(err, &apiErr):
		res.Reachable = true
		return res, err
	case err != nil:
		return res, err
	}
	res.Reachable = true
	res.TokenValid = true
	res.Version = hdr.Get("X-DefectDojo-Version")
	var prof profile
	if err := json.Unmarshal(body, &prof); err != nil {
		return res, fmt.Errorf("defectdojo user_profile/: decode response: %w", err)
	}
	res.User = prof.User.Username
	res.CanImport = prof.canImport()

	if product != "" {
		q := url.Values{"name_exact": {product}, "limit": {"1"}}
		body, _, err := c.get(ctx, "products/?"+q.Encode())
		if err != nil {
			return res, err
		}
		var list struct {
			Count int `json:"count"`
		}
		if err := json.Unmarshal(body, &list); err != nil {
			return res, fmt.Errorf("defectdojo products/: decode response: %w", err)
		}
		res.ProductExists = list.Count > 0
	}
	return res, nil
}

type member struct {
	Role int `json:"role"`
}

type profile struct {
	User struct {
		Username    string `json:"username"`
		IsSuperuser bool   `json:"is_superuser"`
	} `json:"user"`
	GlobalRole        *member  `json:"global_role"`
	ProductTypeMember []member `json:"product_type_member"`
	ProductMember     []member `json:"product_member"`
}

// canImport is a best-effort answer: true for superusers and for any direct
// membership (global, product type or product) with a role that may import.
// DefectDojo role ids: 1 API_Importer, 2 Writer, 3 Maintainer, 4 Owner,
// 5 Reader. Permissions inherited through groups are not considered, so
// false can be a false negative; the import itself is the final judge.
func (p profile) canImport() bool {
	if p.User.IsSuperuser {
		return true
	}
	ok := func(m member) bool { return m.Role >= 1 && m.Role <= 4 }
	if p.GlobalRole != nil && ok(*p.GlobalRole) {
		return true
	}
	for _, m := range p.ProductTypeMember {
		if ok(m) {
			return true
		}
	}
	for _, m := range p.ProductMember {
		if ok(m) {
			return true
		}
	}
	return false
}

// Reimport uploads a Generic Findings file with /api/v2/reimport-scan/.
// With auto_create_context DefectDojo creates product type, product,
// engagement and test on the first call and reimports into the test on later
// ones. DefectDojo matches findings on reimport by its legacy hash (title,
// cwe, line, file_path, description) for this parser, not by
// unique_id_from_tool, which is why BuildFindings keeps title and
// description to stable identity. CloseOldFindings closes findings missing
// from the file.
func (c *Client) Reimport(ctx context.Context, p PushParams, findings []byte) (ImportResult, error) {
	if len(findings) > MaxUploadBytes {
		return ImportResult{}, fmt.Errorf("findings file is %d bytes, limit is %d", len(findings), MaxUploadBytes)
	}
	if err := Validate(findings); err != nil {
		return ImportResult{}, fmt.Errorf("refusing to push invalid file: %w", err)
	}
	p = p.withDefaults()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fields := [][2]string{
		{"scan_type", ScanType},
		{"product_type_name", p.ProductType},
		{"product_name", p.Product},
		{"engagement_name", p.Engagement},
		{"test_title", p.TestTitle},
		{"auto_create_context", "true"},
		{"deduplication_on_engagement", "true"},
		{"active", "true"},
		{"verified", "false"},
		{"minimum_severity", "Info"},
		{"do_not_reactivate", "false"},
		{"close_old_findings", strconv.FormatBool(p.CloseOldFindings)},
	}
	for _, f := range fields {
		if err := mw.WriteField(f[0], f[1]); err != nil {
			return ImportResult{}, err
		}
	}
	fw, err := mw.CreateFormFile("file", "rampart-findings.json")
	if err != nil {
		return ImportResult{}, err
	}
	if _, err := fw.Write(findings); err != nil {
		return ImportResult{}, err
	}
	if err := mw.Close(); err != nil {
		return ImportResult{}, err
	}
	u, err := c.api("reimport-scan/")
	if err != nil {
		return ImportResult{}, err
	}
	if c.hc.Timeout == 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, reimportTimeout)
		defer cancel()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, &buf)
	if err != nil {
		return ImportResult{}, err
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	body, _, err := c.do(req, "reimport-scan/")
	if err != nil {
		return ImportResult{}, err
	}
	var out ImportResult
	if len(body) > 0 {
		if err := json.Unmarshal(body, &out); err != nil {
			return ImportResult{}, fmt.Errorf("defectdojo reimport-scan/: decode response: %w", err)
		}
	}
	return out, nil
}

func (c *Client) api(path string) (string, error) {
	u, err := url.Parse(c.base)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return "", errors.New("invalid DefectDojo URL: must be http(s)://host")
	}
	return u.String() + "/api/v2/" + path, nil
}

func (c *Client) get(ctx context.Context, path string) ([]byte, http.Header, error) {
	u, err := c.api(path)
	if err != nil {
		return nil, nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, nil, err
	}
	return c.do(req, path)
}

// do sends req with the token and returns the (capped) body of a 2xx reply.
// Error text never contains the token.
func (c *Client) do(req *http.Request, path string) ([]byte, http.Header, error) {
	req.Header.Set("Accept", "application/json")
	if c.token != "" {
		req.Header.Set("Authorization", "Token "+c.token)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return nil, nil, fmt.Errorf("defectdojo %s: %s", path, c.redact(err.Error()))
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxResponseBytes+1))
	if err != nil {
		return nil, nil, fmt.Errorf("defectdojo %s: read response: %s", path, c.redact(err.Error()))
	}
	if len(body) > MaxResponseBytes {
		return nil, nil, fmt.Errorf("defectdojo %s: response larger than %d bytes", path, MaxResponseBytes)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		msg := strings.TrimSpace(string(body))
		if len(msg) > maxErrorBody {
			msg = msg[:maxErrorBody] + "..."
		}
		return nil, resp.Header, &APIError{Path: path, Status: resp.StatusCode, Body: c.redact(msg)}
	}
	return body, resp.Header, nil
}

func (c *Client) redact(s string) string {
	if c.token == "" {
		return s
	}
	return strings.ReplaceAll(s, c.token, "[redacted]")
}
