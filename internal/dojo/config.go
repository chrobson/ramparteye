package dojo

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"

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
	Token string
	// TokenSet reports whether an API token is configured.
	TokenSet bool
	// AutoPush only takes effect once URL and token are configured.
	AutoPush     bool
	CloseMissing bool
	// ManagedByEnv is true when RAMPART_DOJO_URL is set: every value then
	// comes from the environment and the UI cannot change it.
	ManagedByEnv bool
}

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
	if tok := strings.TrimSpace(s.Token); tok != "" {
		if strings.ContainsAny(tok, "\r\n\x00") {
			return errors.New("DefectDojo token must not contain control characters")
		}
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
		if cfg.DojoToken == "" {
			return "", ErrNoToken
		}
		return cfg.DojoToken, nil
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

// normaliseURL requires an absolute http(s) URL with a host and without
// userinfo, query or fragment, and strips trailing slashes.
func normaliseURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	bad := func(why string) (string, error) {
		return "", fmt.Errorf("DefectDojo URL %q: %s", raw, why)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return bad("not a valid URL")
	}
	if s := strings.ToLower(u.Scheme); s != "http" && s != "https" {
		return bad("must be an absolute http or https URL")
	}
	if u.Hostname() == "" {
		return bad("host is required")
	}
	if u.User != nil {
		return bad("must not contain credentials")
	}
	if strings.ContainsAny(raw, "?#") {
		return bad("must not contain a query or fragment")
	}
	return strings.TrimRight(raw, "/"), nil
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}
