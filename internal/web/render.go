package web

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/chrobson/ramparteye/internal/auth"
	"github.com/chrobson/ramparteye/internal/model"
)

// View is the data every page template receives. Shell is nil on bare
// pages (login, forced password change, errors without a session); page
// content reads its own data from Data.
type View struct {
	Shell *Shell
	Ctx   context.Context
	Data  any
}

// pages holds one template set per page: layout.html and components plus
// the page file, which defines "title" and "content".
type pages struct {
	set map[string]*template.Template
}

func parsePages(fsys fs.FS, funcs template.FuncMap) (*pages, error) {
	base, err := template.New("layout.html").Funcs(funcs).ParseFS(fsys, "layout.html", "components/*.html")
	if err != nil {
		return nil, fmt.Errorf("parse layout: %w", err)
	}
	names, err := fs.Glob(fsys, "*.html")
	if err != nil {
		return nil, err
	}
	p := &pages{set: map[string]*template.Template{}}
	for _, name := range names {
		if name == "layout.html" {
			continue
		}
		t, err := base.Clone()
		if err != nil {
			return nil, err
		}
		if t, err = t.ParseFS(fsys, name); err != nil {
			return nil, fmt.Errorf("parse %s: %w", name, err)
		}
		p.set[strings.TrimSuffix(name, ".html")] = t
	}
	return p, nil
}

func (s *Server) funcs() template.FuncMap {
	return template.FuncMap{
		"sevClass":    sevClass,
		"changeClass": changeClass,
		"changeLabel": changeLabel,
		"ago":         agoFunc(s.now),
		"can":         can,
		"num":         num,
		"dict":        dict,
		"cellOf":      cellOf,
		"asset":       assetFunc(s.static),
	}
}

// render writes page with status 200.
func (s *Server) render(w http.ResponseWriter, r *http.Request, page string, data any) {
	s.renderStatus(w, r, http.StatusOK, page, data)
}

// renderStatus executes page into a buffer first, so a template error
// yields a clean 500 page instead of half a page.
func (s *Server) renderStatus(w http.ResponseWriter, r *http.Request, status int, page string, data any) {
	if err := s.execute(w, r, status, page, data); err != nil {
		s.log.Error("render page", "page", page, "path", r.URL.Path, "err", err)
		s.serverError(w, r)
	}
}

func (s *Server) execute(w http.ResponseWriter, r *http.Request, status int, page string, data any) error {
	t, ok := s.pages.set[page]
	if !ok {
		return fmt.Errorf("unknown page %q", page)
	}
	v := View{Ctx: r.Context(), Data: data}
	layout := "bare"
	if u, ok := auth.CurrentUser(r.Context()); ok && !u.MustChangePassword {
		sh := s.shell(r, u)
		v.Shell, layout = &sh, "layout"
	}
	var buf bytes.Buffer
	if err := t.ExecuteTemplate(&buf, layout, v); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = buf.WriteTo(w)
	return nil
}

// sevClass maps a severity to its badge class; unknown values are Info.
func sevClass(s model.Severity) string {
	switch s {
	case model.SevCritical:
		return "sev-crit"
	case model.SevHigh:
		return "sev-high"
	case model.SevMedium:
		return "sev-med"
	case model.SevLow:
		return "sev-low"
	default:
		return "sev-info"
	}
}

// changeClass maps a change kind to its tag class.
func changeClass(k model.ChangeKind) string {
	switch k {
	case model.ChangeNew:
		return "tag-new"
	case model.ChangeGone, model.ChangeHostDown:
		return "tag-gone"
	case model.ChangeHostUp:
		return "tag-up"
	case model.ChangeUnstable:
		return "tag-flap"
	default:
		return "tag-changed"
	}
}

// changeLabel is the display text of a change kind ("host_up" -> "host up").
func changeLabel(k model.ChangeKind) string { return strings.ReplaceAll(string(k), "_", " ") }

// agoFunc returns a formatter of a past time relative to now.
func agoFunc(now func() time.Time) func(time.Time) string {
	return func(t time.Time) string {
		if t.IsZero() {
			return "never"
		}
		d := now().Sub(t)
		switch {
		case d < time.Minute:
			return "just now"
		case d < time.Hour:
			return strconv.Itoa(int(d/time.Minute)) + " min ago"
		case d < 48*time.Hour:
			return strconv.Itoa(int(d/time.Hour)) + " h ago"
		default:
			return strconv.Itoa(int(d/(24*time.Hour))) + " d ago"
		}
	}
}

// can reports whether the context's user holds perm. An unknown permission
// name is a template error, so a typo cannot silently hide a control.
func can(ctx context.Context, perm string) (bool, error) {
	if !auth.ValidPerm(perm) {
		return false, fmt.Errorf("can: unknown permission %q", perm)
	}
	return auth.Can(ctx, auth.Perm(perm)), nil
}

// num formats an integer with thousands separators.
func num(n int) string {
	s := strconv.Itoa(n)
	neg := strings.HasPrefix(s, "-")
	s = strings.TrimPrefix(s, "-")
	var b strings.Builder
	if neg {
		b.WriteByte('-')
	}
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			b.WriteByte(',')
		}
		b.WriteRune(c)
	}
	return b.String()
}

// dict builds a map from key/value pairs, for passing several values to a
// component template.
func dict(kv ...any) (map[string]any, error) {
	if len(kv)%2 != 0 {
		return nil, errors.New("dict: odd number of arguments")
	}
	m := make(map[string]any, len(kv)/2)
	for i := 0; i < len(kv); i += 2 {
		k, ok := kv[i].(string)
		if !ok {
			return nil, fmt.Errorf("dict: key %v is not a string", kv[i])
		}
		m[k] = kv[i+1]
	}
	return m, nil
}

// Cell is a table value prepared for display: Full is valid UTF-8, Short
// its first runes when Truncated.
type Cell struct {
	Short, Full string
	Truncated   bool
}

// cellOf prepares v for a table cell of at most maxRunes runes.
func cellOf(v string, maxRunes int) Cell {
	full := strings.ToValidUTF8(v, "�")
	if utf8.RuneCountInString(full) <= maxRunes {
		return Cell{Short: full, Full: full}
	}
	return Cell{Short: truncate(full, maxRunes), Full: full, Truncated: true}
}

// truncate returns the first n runes of s (invalid UTF-8 replaced).
func truncate(s string, n int) string {
	s = strings.ToValidUTF8(s, "�")
	i := 0
	for j := range s {
		if i == n {
			return s[:j]
		}
		i++
	}
	return s
}

// assetFunc returns the URL of a static file with a content hash, so the
// files can be cached and still change on upgrade. Hashes are computed
// once, up front.
func assetFunc(static fs.FS) func(string) (string, error) {
	hashes := map[string]string{}
	_ = fs.WalkDir(static, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := fs.ReadFile(static, p)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(b)
		hashes[p] = hex.EncodeToString(sum[:6])
		return nil
	})
	return func(name string) (string, error) {
		h, ok := hashes[name]
		if !ok {
			return "", fmt.Errorf("asset %q not found", name)
		}
		return "/static/" + name + "?v=" + h, nil
	}
}
