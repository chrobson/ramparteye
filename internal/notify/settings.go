package notify

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/chrobson/ramparteye/internal/secret"
	"github.com/chrobson/ramparteye/internal/store"
	"github.com/chrobson/ramparteye/internal/urlcheck"
)

// Message formats.
const (
	FormatJSON  = "json"
	FormatSlack = "slack"
)

// The sealed values are bound to their columns, so one cannot be replayed
// into the other.
const (
	urlAAD    = "notify_config:url"
	secretAAD = "notify_config:secret"
)

const (
	// maxURLLen bounds the webhook URL.
	maxURLLen = 2048
	// maxSecretLen bounds the signing secret.
	maxSecretLen = 512
)

var (
	// ErrNotConfigured is returned by SendTest when no webhook URL is
	// stored. Nothing is sent and nothing is recorded.
	ErrNotConfigured = errors.New("no webhook URL configured")
	// ErrNoURL refuses to enable notifications without a webhook URL.
	ErrNoURL = errors.New("set a webhook URL to enable notifications")
	// ErrURLUnavailable marks a stored webhook URL or signing secret that
	// cannot be used: it does not open with the current key.
	ErrURLUnavailable = errors.New("webhook URL unavailable")
)

// SettingsStore is the persistence of the settings; *store.Store satisfies it.
type SettingsStore interface {
	NotifyConfig(ctx context.Context) (store.NotifyConfig, error)
	SaveNotifyConfig(ctx context.Context, c store.NotifyConfig) error
}

var _ SettingsStore = (*store.Store)(nil)

// Settings are the webhook notifications as edited in the UI. URL and
// Secret are write-only: SaveSettings seals them, LoadSettings never fills
// them (see URLSet, SecretSet). An empty URL or Secret on save keeps the
// stored value.
type Settings struct {
	Enabled bool
	URL     string `json:"-"`
	// ClearURL removes the stored URL; it cannot be combined with URL.
	ClearURL bool
	// URLSet reports whether a webhook URL is stored; Endpoint is its
	// scheme and host, the only part that is shown.
	URLSet   bool
	Endpoint string
	Format   string // json | slack
	Secret   string `json:"-"`
	// ClearSecret removes the stored secret; it cannot be combined with
	// Secret.
	ClearSecret bool
	SecretSet   bool
	// OnlyChanges skips a finished run without changes.
	OnlyChanges bool
	// NotifyFailed also notifies runs that ended failed.
	NotifyFailed bool
	// BaseURL is the public URL of this instance, used for links ("" =
	// no links).
	BaseURL string
}

func (s Settings) redacted() any {
	type plain Settings
	p := plain(s)
	if s.URL != "" {
		p.URL = "[redacted]"
	}
	if s.Secret != "" {
		p.Secret = "[redacted]"
	}
	return p
}

// String formats s with the credentials masked.
func (s Settings) String() string { return fmt.Sprintf("%+v", s.redacted()) }

// GoString is String for %#v.
func (s Settings) GoString() string { return fmt.Sprintf("%#v", s.redacted()) }

// LoadSettings returns the stored settings, without credentials; a missing
// row gives the defaults (off, JSON, only when something changed).
func LoadSettings(ctx context.Context, st SettingsStore) (Settings, error) {
	row, err := st.NotifyConfig(ctx)
	if errors.Is(err, store.ErrNotFound) {
		row, err = store.NotifyConfig{Format: FormatJSON, OnlyChanges: true}, nil
	}
	if err != nil {
		return Settings{}, fmt.Errorf("load notification settings: %w", err)
	}
	return Settings{Enabled: row.Enabled, URLSet: len(row.URLEnc) > 0, Endpoint: row.Endpoint, Format: row.Format,
		SecretSet: len(row.SecretEnc) > 0, OnlyChanges: row.OnlyChanges, NotifyFailed: row.NotifyFailed,
		BaseURL: row.BaseURL}, nil
}

// SaveSettings validates s and stores it with URL and secret sealed by box.
// Errors never include the URL or the secret.
func SaveSettings(ctx context.Context, st SettingsStore, box *secret.Box, s Settings) error {
	row := store.NotifyConfig{Enabled: s.Enabled, Format: s.Format, OnlyChanges: s.OnlyChanges,
		NotifyFailed: s.NotifyFailed, ClearURL: s.ClearURL, ClearSecret: s.ClearSecret}
	if row.Format == "" {
		row.Format = FormatJSON
	}
	if row.Format != FormatJSON && row.Format != FormatSlack {
		return errors.New("format must be json or slack")
	}
	if strings.TrimSpace(s.BaseURL) != "" {
		u, err := urlcheck.Parse(s.BaseURL, false)
		if err != nil {
			return errors.New("public base URL " + err.Error())
		}
		row.BaseURL = urlcheck.Origin(u) + strings.TrimRight(u.EscapedPath(), "/")
	}
	raw := strings.TrimSpace(s.URL)
	if raw != "" && s.ClearURL {
		return errors.New("webhook URL cannot be both set and removed")
	}
	var hook *url.URL
	if raw != "" {
		if len(raw) > maxURLLen {
			return fmt.Errorf("webhook URL is longer than %d bytes", maxURLLen)
		}
		u, err := urlcheck.Parse(raw, true)
		if err != nil {
			return errors.New("webhook URL " + err.Error())
		}
		hook = u
	}
	sec, err := secret.Clean(s.Secret, "signing secret", maxSecretLen)
	if err != nil {
		return err
	}
	if sec != "" && s.ClearSecret {
		return errors.New("signing secret cannot be both set and removed")
	}
	if s.Enabled && hook == nil {
		cur, err := LoadSettings(ctx, st)
		if err != nil {
			return err
		}
		if !cur.URLSet || s.ClearURL {
			return ErrNoURL
		}
	}
	if hook != nil || sec != "" {
		if box == nil {
			return errors.New("webhook credentials cannot be stored: no encryption key")
		}
	}
	if hook != nil {
		if row.URLEnc, err = box.Seal([]byte(hook.String()), urlAAD); err != nil {
			return fmt.Errorf("seal webhook URL: %w", err)
		}
		row.Endpoint = urlcheck.Origin(hook)
	}
	if sec != "" {
		if row.SecretEnc, err = box.Seal([]byte(sec), secretAAD); err != nil {
			return fmt.Errorf("seal signing secret: %w", err)
		}
	}
	return st.SaveNotifyConfig(ctx, row)
}

// target is where a delivery goes: the opened webhook URL and secret.
type target struct {
	url    *url.URL
	secret string // "" = unsigned
}

// unavailable is a loadTarget failure caused by the sealed values, not by
// the store; it matches ErrURLUnavailable.
type unavailable struct{ msg string }

func (e unavailable) Error() string { return e.msg }
func (e unavailable) Unwrap() error { return ErrURLUnavailable }

// loadTarget opens the stored webhook URL and signing secret. It returns
// ErrNotConfigured when no URL is stored. For the notifier; never shown.
func loadTarget(ctx context.Context, st SettingsStore, box *secret.Box) (target, error) {
	row, err := st.NotifyConfig(ctx)
	if errors.Is(err, store.ErrNotFound) || (err == nil && len(row.URLEnc) == 0) {
		return target{}, ErrNotConfigured
	}
	if err != nil {
		return target{}, fmt.Errorf("load notification settings: %w", err)
	}
	if box == nil {
		return target{}, unavailable{"webhook URL cannot be opened: no encryption key"}
	}
	plain, err := box.Open(row.URLEnc, urlAAD)
	if err != nil {
		return target{}, unavailable{"webhook URL cannot be opened with the current key (re-enter it in Settings)"}
	}
	u, err := urlcheck.Parse(string(plain), true)
	if err != nil {
		return target{}, unavailable{"stored webhook URL is invalid (re-enter it in Settings)"}
	}
	t := target{url: u}
	if len(row.SecretEnc) > 0 {
		sec, err := box.Open(row.SecretEnc, secretAAD)
		if err != nil {
			return target{}, unavailable{"signing secret cannot be opened with the current key (re-enter it in Settings)"}
		}
		t.secret = string(sec)
	}
	return t, nil
}
