package web

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/go-chi/chi/v5"

	"github.com/chrobson/ramparteye/internal/auth"
	"github.com/chrobson/ramparteye/internal/model"
	"github.com/chrobson/ramparteye/internal/store"
)

// Limits of an annotation.
const (
	maxComment = 4000 // runes
	maxTags    = 20
	maxTagLen  = 40 // runes
)

var annotationSeverities = []model.Severity{model.SevInfo, model.SevLow, model.SevMedium, model.SevHigh,
	model.SevCritical}

// AnnotationForm is the annotation panel of a host or service page. Viewers
// (CanEdit false) see the stored annotation read-only.
type AnnotationForm struct {
	CanEdit       bool
	Exists        bool
	Action        string // POST target of save
	DeleteAction  string
	Comment       string
	Tags          string // comma separated
	Severity      string
	FalsePositive bool
	UpdatedAt     time.Time
	Error         string
	Severities    []model.Severity
}

func annotationAction(k model.AssetKey, suffix string) string {
	p := assetPath(k)
	path, query, _ := strings.Cut(p, "?")
	path += "/annotation" + suffix
	if query != "" {
		path += "?" + query
	}
	return path
}

func newAnnotationForm(ctx context.Context, k model.AssetKey, a store.Annotation, exists bool) AnnotationForm {
	f := AnnotationForm{CanEdit: auth.Can(ctx, auth.PermResultsEdit), Exists: exists, Action: annotationAction(k, ""),
		DeleteAction: annotationAction(k, "/delete"),
		Severities:   annotationSeverities}
	if exists {
		f.Comment, f.Tags = a.Comment, strings.Join(a.Tags, ", ")
		f.Severity, f.FalsePositive, f.UpdatedAt = a.Severity, a.FalsePositive, a.UpdatedAt
	}
	return f
}

// annotationFor returns the form of key: the stored annotation, or form's
// submitted values after a rejected submission.
func (s *Server) annotationFor(ctx context.Context, k model.AssetKey, override *AnnotationForm) (AnnotationForm, error) {
	a, err := s.d.Store.Annotation(ctx, k)
	exists := err == nil
	if err != nil && !errors.Is(err, store.ErrAnnotationNotFound) {
		return AnnotationForm{}, err
	}
	f := newAnnotationForm(ctx, k, a, exists)
	if override != nil {
		f.Comment, f.Tags, f.Severity, f.FalsePositive, f.Error = override.Comment, override.Tags, override.Severity,
			override.FalsePositive, override.Error
	}
	return f, nil
}

// annotationKey reads the key from the URL: a host (port 0) or a service.
func annotationKey(r *http.Request) (model.AssetKey, bool) {
	if chi.URLParam(r, "port") == "" {
		ip, ok := parseIP(chi.URLParam(r, "ip"))
		return model.AssetKey{IP: ip}, ok
	}
	return serviceKey(r)
}

// knownHost reports whether ip is a tracked host.
func (s *Server) knownHost(ctx context.Context, ip model.AssetKey) (bool, error) {
	hs, err := s.d.Store.HostStates(ctx, "")
	if err != nil {
		return false, err
	}
	for _, h := range hs {
		if h.IP.Unmap() == ip.IP {
			return true, nil
		}
	}
	return false, nil
}

// parseTags splits a comma separated list, dropping blanks and duplicates.
func parseTags(raw string) ([]string, error) {
	var tags []string
	seen := map[string]bool{}
	for _, t := range strings.Split(raw, ",") {
		t = strings.TrimSpace(t)
		if t == "" || seen[t] {
			continue
		}
		if utf8.RuneCountInString(t) > maxTagLen {
			return nil, errors.New("a tag is longer than 40 characters")
		}
		if strings.IndexFunc(t, unicode.IsControl) >= 0 {
			return nil, errors.New("tags cannot contain control characters")
		}
		seen[t] = true
		tags = append(tags, t)
	}
	if len(tags) > maxTags {
		return nil, errors.New("at most 20 tags are allowed")
	}
	return tags, nil
}

// annotationInput validates the submitted form into an annotation (key and
// user are set by the caller) and echoes the cleaned values in form.
func annotationInput(r *http.Request) (store.Annotation, AnnotationForm, error) {
	f := AnnotationForm{
		Comment:       strings.ReplaceAll(strings.ToValidUTF8(r.PostFormValue("comment"), "�"), "\r\n", "\n"),
		Tags:          strings.ToValidUTF8(r.PostFormValue("tags"), "�"),
		Severity:      r.PostFormValue("severity"),
		FalsePositive: r.PostFormValue("false_positive") != "",
	}
	a := store.Annotation{Comment: f.Comment, Severity: f.Severity, FalsePositive: f.FalsePositive}
	if utf8.RuneCountInString(f.Comment) > maxComment {
		return a, f, errors.New("the comment is longer than 4000 characters")
	}
	if f.Severity != "" {
		ok := false
		for _, s := range annotationSeverities {
			ok = ok || string(s) == f.Severity
		}
		if !ok {
			return a, f, errors.New("unknown severity")
		}
	}
	tags, err := parseTags(f.Tags)
	a.Tags = tags
	return a, f, err
}

// annotationSave handles POST .../annotation.
func (s *Server) annotationSave(w http.ResponseWriter, r *http.Request) {
	key, ok := annotationKey(r)
	if !ok {
		s.notFound(w, r)
		return
	}
	known, err := s.knownHost(r.Context(), key)
	if err != nil {
		s.log.Error("annotation: host lookup", "err", err)
		s.serverError(w, r)
		return
	}
	if known && key.Port != 0 {
		known, err = s.serviceKnown(r.Context(), key)
	}
	if err != nil {
		s.log.Error("annotation: asset lookup", "err", err)
		s.serverError(w, r)
		return
	}
	if !known {
		s.notFound(w, r)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	if err := r.ParseForm(); err != nil {
		s.renderError(w, r, errorData{Code: http.StatusBadRequest, Title: "Bad request",
			Text: "The form could not be read."})
		return
	}
	a, form, verr := annotationInput(r)
	if verr != nil {
		form.Error = "Annotation not saved: " + verr.Error() + "."
		if key.Port == 0 {
			s.renderHost(w, r, http.StatusUnprocessableEntity, key.IP, &form)
		} else {
			s.renderService(w, r, http.StatusUnprocessableEntity, key, &form)
		}
		return
	}
	u, _ := auth.CurrentUser(r.Context())
	a.Key, a.UpdatedBy = key, u.ID
	if _, err := s.d.Store.UpsertAnnotation(r.Context(), a); err != nil {
		s.log.Error("save annotation", "err", err)
		s.serverError(w, r)
		return
	}
	setFlash(w, r, "Annotation saved.")
	http.Redirect(w, r, assetPath(key), http.StatusSeeOther)
}

// annotationDelete handles POST .../annotation/delete.
func (s *Server) annotationDelete(w http.ResponseWriter, r *http.Request) {
	key, ok := annotationKey(r)
	if !ok {
		s.notFound(w, r)
		return
	}
	u, _ := auth.CurrentUser(r.Context())
	msg := "Annotation removed."
	switch err := s.d.Store.DeleteAnnotation(r.Context(), key, u.ID); {
	case errors.Is(err, store.ErrAnnotationNotFound):
		msg = "There was no annotation to remove."
	case err != nil:
		s.log.Error("delete annotation", "err", err)
		s.serverError(w, r)
		return
	}
	setFlash(w, r, msg)
	http.Redirect(w, r, assetPath(key), http.StatusSeeOther)
}

// serviceKnown reports whether key is a service of the latest run or one
// that a scan saw or changed before.
func (s *Server) serviceKnown(ctx context.Context, key model.AssetKey) (bool, error) {
	snap, err := s.loadSnapshot(ctx)
	if err != nil {
		return false, err
	}
	for _, sv := range snap.Services[key.IP] {
		if sv.Key == key {
			return true, nil
		}
	}
	h, err := s.d.Store.AssetHistory(ctx, key, availabilityRuns)
	if err != nil {
		return false, err
	}
	for _, r := range h.Runs {
		if r.Seen {
			return true, nil
		}
	}
	return len(h.Changes) > 0, nil
}
