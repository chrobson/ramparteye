package web

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/chrobson/ramparteye/internal/auth"
	"github.com/chrobson/ramparteye/internal/notify"
	"github.com/chrobson/ramparteye/internal/store"
)

const (
	// deliveryHistoryRows is the length of the delivery history.
	deliveryHistoryRows = 20
	// notifyTestTimeout bounds "Send test notification" (three attempts
	// with backoff fit in it).
	notifyTestTimeout = 45 * time.Second
)

// Notifier stores the webhook settings, sends test notifications and
// reads the delivery history; *notify.Notifier satisfies it.
type Notifier interface {
	Settings(ctx context.Context) (notify.Settings, error)
	SaveSettings(ctx context.Context, s notify.Settings) error
	Deliveries(ctx context.Context, limit int) ([]store.NotifyDelivery, error)
	SendTest(ctx context.Context) (notify.Delivery, error)
}

var _ Notifier = (*notify.Notifier)(nil)

// NotifyData is the Settings → Notifications tab. Settings never carries
// the webhook URL or the signing secret.
type NotifyData struct {
	Tabs      []SettingsTab
	Available bool
	Settings  notify.Settings
	Status    string // off | enabled · ... | last delivery failed
	StatusOK  bool
	Error     string
	Test      *CheckRow // outcome of "Send test notification"
	History   []DeliveryRow
}

// DeliveryRow is one row of the delivery history.
type DeliveryRow struct {
	Run      string // #id or test
	At       time.Time
	Trigger  string
	Event    string
	Attempts int
	Result   string
	State    string // ok | bad
}

func (s *Server) notifyPage(w http.ResponseWriter, r *http.Request) {
	s.renderNotify(w, r, http.StatusOK, NotifyData{})
}

// renderNotify fills the settings (unless d already holds a submitted
// form), the status and the history, and renders the tab.
func (s *Server) renderNotify(w http.ResponseWriter, r *http.Request, status int, d NotifyData) {
	ctx := r.Context()
	d.Tabs = tabs(r, "/settings/notifications")
	n := s.d.Notifier
	if n == nil {
		d.Error = "Notifications are not available in this process."
		d.Settings = notify.Settings{Format: notify.FormatJSON, OnlyChanges: true}
		s.renderStatus(w, r, status, "settings-notifications", d)
		return
	}
	d.Available = true
	if d.Settings.Format == "" {
		st, err := n.Settings(ctx)
		if err != nil {
			s.log.Error("notification settings", "err", err)
			if d.Error == "" {
				d.Error = "The notification settings could not be loaded: " + err.Error()
			}
		}
		d.Settings = st
	}
	d.Settings.URL, d.Settings.Secret = "", ""
	ds, err := n.Deliveries(ctx, deliveryHistoryRows)
	if err != nil {
		s.log.Error("notification history", "err", err)
	}
	for _, x := range ds {
		d.History = append(d.History, deliveryRow(x))
	}
	switch {
	case !d.Settings.Enabled:
		d.Status = "off"
	case len(ds) == 0:
		d.Status = "enabled · nothing sent yet"
	case !ds[0].OK:
		d.Status = "enabled · last delivery failed"
	default:
		d.Status, d.StatusOK = "enabled", true
	}
	s.renderStatus(w, r, status, "settings-notifications", d)
}

func deliveryRow(x store.NotifyDelivery) DeliveryRow {
	row := DeliveryRow{Run: "test", At: x.At, Trigger: x.Trigger, Event: x.Event, Attempts: x.Attempts,
		State: "bad", Result: x.Error}
	if x.RunID != nil {
		row.Run = "#" + strconv.FormatInt(*x.RunID, 10)
	} else if x.Trigger != notify.TriggerTest {
		row.Run = "–"
	}
	if x.OK {
		row.State, row.Result = "ok", "delivered"
		if x.Status != nil {
			row.Result += " (HTTP " + strconv.Itoa(*x.Status) + ")"
		}
	} else if row.Result == "" {
		row.Result = "failed"
	}
	return row
}

// readNotifyForm reads the notification form. URL and secret come from
// r.FormValue because Settings never serialises them.
func readNotifyForm(r *http.Request) notify.Settings {
	v := func(k string) string { return strings.TrimSpace(r.PostForm.Get(k)) }
	return notify.Settings{Enabled: v("enabled") != "", URL: r.FormValue("url"), ClearURL: v("clear_url") != "",
		Format: v("format"), Secret: r.FormValue("secret"), ClearSecret: v("clear_secret") != "",
		OnlyChanges: v("only_changes") != "", NotifyFailed: v("notify_failed") != "", BaseURL: v("base_url")}
}

func (s *Server) notifySave(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	if err := r.ParseForm(); err != nil {
		s.renderNotify(w, r, http.StatusBadRequest, NotifyData{Error: "The form could not be read."})
		return
	}
	if s.d.Notifier == nil {
		s.renderNotify(w, r, http.StatusServiceUnavailable, NotifyData{})
		return
	}
	in := readNotifyForm(r)
	if err := s.d.Notifier.SaveSettings(r.Context(), in); err != nil {
		// Show the submitted form again, credentials left out.
		cur, _ := s.d.Notifier.Settings(r.Context())
		in.URL, in.Secret = "", ""
		in.URLSet, in.SecretSet, in.Endpoint = cur.URLSet, cur.SecretSet, cur.Endpoint
		if in.Format == "" {
			in.Format = notify.FormatJSON
		}
		s.renderNotify(w, r, http.StatusUnprocessableEntity, NotifyData{Settings: in, Error: sentence(err.Error())})
		return
	}
	u, _ := auth.CurrentUser(r.Context())
	s.audit(r, &u.ID, "notify.settings", "notify_config", map[string]any{
		"enabled": in.Enabled, "format": in.Format, "only_changes": in.OnlyChanges, "notify_failed": in.NotifyFailed,
		"base_url": in.BaseURL, "url_changed": strings.TrimSpace(in.URL) != "", "url_cleared": in.ClearURL,
		"secret_changed": strings.TrimSpace(in.Secret) != "", "secret_cleared": in.ClearSecret})
	setFlash(w, r, "Notification settings saved.")
	http.Redirect(w, r, "/settings/notifications", http.StatusSeeOther)
}

// notifyTest sends a test notification with the stored settings and shows
// the outcome inline. It finishes and is recorded even if the browser goes
// away.
func (s *Server) notifyTest(w http.ResponseWriter, r *http.Request) {
	if s.d.Notifier == nil {
		s.renderNotify(w, r, http.StatusServiceUnavailable, NotifyData{})
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), notifyTestTimeout)
	res, err := s.d.Notifier.SendTest(ctx)
	cancel()
	var d NotifyData
	switch {
	case errors.Is(err, notify.ErrNotConfigured):
		d.Error = "Save a webhook URL first."
	case err != nil && res.Event == "":
		// Nothing was sent: settings unreadable or the notifier closed.
		d.Error = "The test notification could not be sent: " + sentence(err.Error())
	case err != nil:
		d.Test = &CheckRow{State: "bad", Text: "Test notification failed: " + res.Error}
	default:
		d.Test = &CheckRow{State: "ok", Text: "Test notification delivered (HTTP " + strconv.Itoa(res.Status) + ")"}
	}
	u, _ := auth.CurrentUser(r.Context())
	s.audit(r, &u.ID, "notify.test", "notify_config", map[string]any{"ok": err == nil, "status": res.Status})
	s.renderNotify(w, r, http.StatusOK, d)
}

// sentence capitalises msg and ends it with a full stop.
func sentence(msg string) string {
	if msg == "" {
		return msg
	}
	msg = strings.ToUpper(msg[:1]) + msg[1:]
	if !strings.HasSuffix(msg, ".") {
		msg += "."
	}
	return msg
}
