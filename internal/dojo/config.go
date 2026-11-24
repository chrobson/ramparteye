package dojo

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"unicode"

	"github.com/chrobson/ramparteye/internal/config"
	"github.com/chrobson/ramparteye/internal/secret"
	"github.com/chrobson/ramparteye/internal/store"
)

// tokenAAD binds the sealed token to its column so it cannot be replayed
// into another sealed field.
const tokenAAD = "dojo_config:token"

var (
	// ErrManagedByEnv is returned by SaveSettings when the DefectDojo
	// connection is configured through RAMPART_DOJO_* variables.
	ErrManagedByEnv = errors.New("DefectDojo settings are managed by environment variables")
	// ErrNoToken is returned by loadToken when no API token is configured.
	ErrNoToken = errors.New("no DefectDojo API token configured")
)

// SettingsStore is the persistence the settings service needs; *store.Store
// satisfies it.
type SettingsStore interface {
	DojoConfig(ctx context.Context) (store.DojoConfig, error)
	SaveDojoConfig(ctx context.Context, c store.DojoConfig) error
}

var _ SettingsStore = (*store.Store)(nil)

// Settings is the DefectDojo connection as edited in the UI.
type Settings struct {
	URL         string
	ProductType string
	Product     string
	Engagement  string
	// Token is write-only: SaveSettings seals it, LoadSettings never fills
	// it (see TokenSet). An empty Token on save keeps the stored token.
	Token string `json:"-"`
	// ClearToken removes the stored token; it cannot be combined with Token.
	ClearToken bool
	// TokenSet reports whether an API token is configured.
	TokenSet bool
	// AutoPush only takes effect once URL and token are configured.
	AutoPush     bool
	CloseMissing bool
	// ManagedByEnv is true when RAMPART_DOJO_URL is set: every value then
	// comes from the environment and the UI cannot change it.
	ManagedByEnv bool
}

func (s Settings) redacted() any {
	type plain Settings
	p := plain(s)
	if s.Token != "" {
		p.Token = "[redacted]"
	}
	return p
}

// String formats s with the token masked.
func (s Settings) String() string { return fmt.Sprintf("%+v", s.redacted()) }

// GoString is String for %#v.
func (s Settings) GoString() string { return fmt.Sprintf("%#v", s.redacted()) }

// LoadSettings returns the effective settings. A non-empty cfg.DojoURL means
// the connection is managed by the environment and every value comes from
// cfg; other RAMPART_DOJO_* values are ignored without it. Otherwise the
// stored row is used, with defaults for an empty or missing row.
func LoadSettings(ctx context.Context, st SettingsStore, _ *secret.Box, cfg config.Config) (Settings, error) {
	if cfg.DojoURL != "" {
		u, err := normaliseURL(cfg.DojoURL)
		if err != nil {
			return Settings{}, fmt.Errorf("RAMPART_DOJO_URL: %w", err)
		}
		if _, err := normaliseToken(cfg.DojoToken); err != nil {
			return Settings{}, fmt.Errorf("RAMPART_DOJO_TOKEN: %w", err)
		}
		return Settings{
			URL:          u,
			ProductType:  orDefault(cfg.DojoProductType, config.DefaultDojoProductType),
			Product:      cfg.DojoProduct,
			Engagement:   orDefault(cfg.DojoEngagement, config.DefaultDojoEngagement),
			TokenSet:     cfg.DojoToken != "",
			AutoPush:     cfg.DojoAutoPush,
			CloseMissing: cfg.DojoCloseMissing,
			ManagedByEnv: true,
		}, nil
	}
	row, err := st.DojoConfig(ctx)
	if errors.Is(err, store.ErrNotFound) {
		row, err = store.DojoConfig{AutoPush: true}, nil
	}
	if err != nil {
		return Settings{}, fmt.Errorf("load DefectDojo settings: %w", err)
	}
	return Settings{
		URL:          row.URL,
		ProductType:  orDefault(row.ProductType, config.DefaultDojoProductType),
		Product:      row.Product,
		Engagement:   orDefault(row.Engagement, config.DefaultDojoEngagement),
		TokenSet:     len(row.TokenEnc) > 0,
		AutoPush:     row.AutoPush,
		CloseMissing: row.CloseMissing,
	}, nil
}

// SaveSettings validates and stores s. It refuses with ErrManagedByEnv when
// the connection comes from the environment. An empty s.Token keeps the
// stored token, a non-empty one replaces it. An empty URL disables DefectDojo.
func SaveSettings(ctx context.Context, st SettingsStore, box *secret.Box, cfg config.Config, s Settings) error {
	if cfg.DojoURL != "" || s.ManagedByEnv {
		return ErrManagedByEnv
	}
	row := store.DojoConfig{
		ProductType:  orDefault(strings.TrimSpace(s.ProductType), config.DefaultDojoProductType),
		Product:      strings.TrimSpace(s.Product),
		Engagement:   orDefault(strings.TrimSpace(s.Engagement), config.DefaultDojoEngagement),
		AutoPush:     s.AutoPush,
		CloseMissing: s.CloseMissing,
	}
	if strings.TrimSpace(s.URL) != "" {
		u, err := normaliseURL(s.URL)
		if err != nil {
			return err
		}
		row.URL = u
	}
	tok, err := normaliseToken(s.Token)
	if err != nil {
		return err
	}
	if tok != "" && s.ClearToken {
		return errors.New("DefectDojo token cannot be both set and cleared")
	}
	row.ClearToken = s.ClearToken
	if tok != "" {
		if box == nil {
			return errors.New("DefectDojo token cannot be stored: no encryption key")
		}
		enc, err := box.Seal([]byte(tok), tokenAAD)
		if err != nil {
			return fmt.Errorf("seal DefectDojo token: %w", err)
		}
		row.TokenEnc = enc
	}
	return st.SaveDojoConfig(ctx, row)
}

// loadToken returns the API token in use: the environment one when managed
// by the environment, otherwise the stored one opened with box. It returns
// ErrNoToken when none is configured. For the pusher; never shown in the UI.
func loadToken(ctx context.Context, st SettingsStore, box *secret.Box, cfg config.Config) (string, error) {
	if cfg.DojoURL != "" {
		tok, err := normaliseToken(cfg.DojoToken)
		if err != nil {
			return "", fmt.Errorf("RAMPART_DOJO_TOKEN: %w", err)
		}
		if tok == "" {
			return "", ErrNoToken
		}
		return tok, nil
	}
	row, err := st.DojoConfig(ctx)
	if errors.Is(err, store.ErrNotFound) {
		return "", ErrNoToken
	}
	if err != nil {
		return "", fmt.Errorf("load DefectDojo token: %w", err)
	}
	if len(row.TokenEnc) == 0 {
		return "", ErrNoToken
	}
	if box == nil {
		return "", errors.New("DefectDojo token cannot be opened: no encryption key")
	}
	plain, err := box.Open(row.TokenEnc, tokenAAD)
	if err != nil {
		return "", fmt.Errorf("open DefectDojo token (re-enter it in Settings): %w", err)
	}
	return string(plain), nil
}

// maxTokenLen bounds an API token; DefectDojo tokens are 40 hex characters.
const maxTokenLen = 512

// normaliseToken trims a token and rejects control characters and excess
// length. Errors never include the token.
func normaliseToken(tok string) (string, error) {
	tok = strings.TrimSpace(tok)
	if len(tok) > maxTokenLen {
		return "", fmt.Errorf("DefectDojo token is longer than %d bytes", maxTokenLen)
	}
	if strings.IndexFunc(tok, unicode.IsControl) >= 0 {
		return "", errors.New("DefectDojo token must not contain control characters")
	}
	return tok, nil
}

// normaliseURL requires an absolute http(s) URL with a host, an optional valid
// port and no userinfo, query or fragment. It lowercases scheme and host and
// strips trailing slashes. Errors are fixed messages: the input may carry
// credentials and is never echoed.
func normaliseURL(raw string) (string, error) {
	bad := func(why string) (string, error) {
		return "", errors.New("DefectDojo URL " + why)
	}
	raw = strings.TrimSpace(raw)
	u, err := url.Parse(raw)
	if err != nil {
		return bad("is not a valid URL")
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return bad("must be an absolute http or https URL")
	}
	if u.Hostname() == "" {
		return bad("needs a host")
	}
	if u.User != nil || strings.Contains(u.Host, "@") {
		return bad("must not contain credentials")
	}
	if u.RawQuery != "" || u.Fragment != "" || strings.ContainsAny(raw, "?#") {
		return bad("must not contain a query or fragment")
	}
	if strings.HasSuffix(u.Host, ":") {
		return bad("has an empty port")
	}
	if p := u.Port(); p != "" {
		if n, err := strconv.Atoi(p); err != nil || n < 1 || n > 65535 {
			return bad("has an invalid port")
		}
	}
	return scheme + "://" + strings.ToLower(u.Host) + strings.TrimRight(u.EscapedPath(), "/"), nil
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}
