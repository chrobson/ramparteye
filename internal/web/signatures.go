package web

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/chrobson/ramparteye/internal/auth"
	"github.com/chrobson/ramparteye/internal/model"
	"github.com/chrobson/ramparteye/internal/sig"
	"github.com/chrobson/ramparteye/internal/store"
)

// Signature page limits.
const (
	// backtestRuns is how many finished scan runs a backtest reads.
	backtestRuns = 30
	// backtestTimeout bounds the evaluation of one backtest.
	backtestTimeout = 20 * time.Second
	// maxBacktestRows caps the matches listed on the page.
	maxBacktestRows = 200
)

// newSignatureYAML is the starting point of the create form.
const newSignatureYAML = `id: my-signature
name: My signature
category: other   # cms|framework|server|iot|admin-panel|staging|other
confidence: 70
description: What this signature detects.
condition: or     # or|and
matchers:
  - type: header
    name: Server
    regex: 'MyServer/(?P<version>[0-9.]+)'
  - type: path      # GET/HEAD only, at most 3 paths, no body, no credentials
    path: /version
    status: [200]
    regex: '"version"'
`

// SigRow is a signature on the list.
type SigRow struct {
	store.SignatureRow
	Category   string
	Confidence int
	Severity   string
	Types      []string
	Invalid    string // parse error of a stored row that no longer validates
}

// SignaturesData is the signature list.
type SignaturesData struct {
	Rows                    []SigRow
	Enabled                 int
	Builtin, Custom, Nuclei int
}

// SignatureData is one signature with its YAML and an optional backtest.
type SignatureData struct {
	Row      store.SignatureRow
	Parsed   *sig.Signature
	Errors   []string
	Backtest *BacktestView
}

// SignatureForm is the create/edit form; YAML holds what was submitted.
type SignatureForm struct {
	Title    string
	New      bool
	Action   string
	EditID   string
	YAML     string
	Errors   []string
	Backtest *BacktestView
}

// BacktestView is the outcome of testing a signature against stored
// history.
type BacktestView struct {
	Runs         int
	Checked      int
	Total        int
	Rows         []BacktestRow
	PathMatchers int
	Stopped      bool
}

// BacktestRow is one historical match.
type BacktestRow struct {
	RunID    int64
	Asset    string
	Href     string
	Evidence string
}

// NucleiItem is one uploaded template in the import report.
type NucleiItem struct {
	File   string
	ID     string
	Name   string
	Reason string
}

// NucleiData is the nuclei import page with the report of an upload.
type NucleiData struct {
	Error    string
	Report   bool
	Imported []NucleiItem
	Rejected []NucleiItem
}

func (s *Server) sigStore() *sig.DBStore { return sig.NewDBStore(s.d.Store) }

func (s *Server) signaturesChanged() {
	if s.d.SignaturesChanged != nil {
		s.d.SignaturesChanged()
	}
}

// problems lists the individual validation problems of err.
func problems(err error) []string {
	var ve *sig.ValidationError
	if errors.As(err, &ve) {
		out := make([]string, 0, len(ve.Problems))
		for _, p := range ve.Problems {
			out = append(out, p.Error())
		}
		return out
	}
	return []string{err.Error()}
}

func (s *Server) signaturesList(w http.ResponseWriter, r *http.Request) {
	rows, err := s.d.Store.Signatures(r.Context())
	if err != nil {
		s.log.Error("signatures", "err", err)
		s.serverError(w, r)
		return
	}
	var d SignaturesData
	for _, row := range rows {
		sr := SigRow{SignatureRow: row}
		if p, err := sig.Parse([]byte(row.YAML)); err != nil {
			sr.Invalid = strings.Join(problems(err), "; ")
		} else {
			sr.Category, sr.Confidence, sr.Severity = p.Category, p.Confidence, p.Severity
			for _, m := range p.Matchers {
				if !slices.Contains(sr.Types, m.Type) {
					sr.Types = append(sr.Types, m.Type)
				}
			}
		}
		if row.Enabled {
			d.Enabled++
		}
		switch row.Source {
		case store.SourceBuiltin:
			d.Builtin++
		case store.SourceNuclei:
			d.Nuclei++
		default:
			d.Custom++
		}
		d.Rows = append(d.Rows, sr)
	}
	s.render(w, r, "signatures", d)
}

// loadSignature loads the {id} signature or writes the error page.
func (s *Server) loadSignature(w http.ResponseWriter, r *http.Request) (store.SignatureRow, bool) {
	row, err := s.d.Store.Signature(r.Context(), chi.URLParam(r, "id"))
	switch {
	case errors.Is(err, store.ErrSignatureNotFound):
		s.notFound(w, r)
		return row, false
	case err != nil:
		s.log.Error("signature", "err", err)
		s.serverError(w, r)
		return row, false
	}
	return row, true
}

func (s *Server) builtinConflict(w http.ResponseWriter, r *http.Request) {
	s.renderError(w, r, errorData{Code: http.StatusConflict, Title: "Built-in signature",
		Text: "Built-in signatures cannot be edited or deleted; you can only enable or disable them."})
}

func (s *Server) signatureView(w http.ResponseWriter, r *http.Request) {
	row, ok := s.loadSignature(w, r)
	if !ok {
		return
	}
	s.renderSignature(w, r, row, nil)
}

func (s *Server) renderSignature(w http.ResponseWriter, r *http.Request, row store.SignatureRow, bt *BacktestView) {
	d := SignatureData{Row: row, Backtest: bt}
	p, err := sig.Parse([]byte(row.YAML))
	if err != nil {
		d.Errors = problems(err)
	} else {
		d.Parsed = p
	}
	s.render(w, r, "signature", d)
}

func (s *Server) signatureNew(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "signature-form", SignatureForm{Title: "New signature", New: true, Action: "/signatures",
		YAML: newSignatureYAML})
}

func (s *Server) signatureEdit(w http.ResponseWriter, r *http.Request) {
	row, ok := s.loadSignature(w, r)
	if !ok {
		return
	}
	if row.IsBuiltin() {
		s.builtinConflict(w, r)
		return
	}
	s.render(w, r, "signature-form", editForm(row.ID, row.YAML))
}

func editForm(id, yaml string) SignatureForm {
	return SignatureForm{Title: "Edit " + id, Action: "/signatures/" + url.PathEscape(id), EditID: id, YAML: yaml}
}

// formYAML reads the yaml field of a bounded form; ok is false when the
// form is too large to read.
func formYAML(w http.ResponseWriter, r *http.Request) (string, bool) {
	r.Body = http.MaxBytesReader(w, r.Body, sig.MaxYAMLBytes+maxFieldBytes)
	if err := r.ParseForm(); err != nil {
		return "", false
	}
	return strings.ReplaceAll(r.PostForm.Get("yaml"), "\r\n", "\n"), true
}

var errYAMLTooLarge = fmt.Sprintf("The form could not be read: the YAML may be at most %d KiB.", sig.MaxYAMLBytes>>10)

func (s *Server) signatureCreate(w http.ResponseWriter, r *http.Request) {
	form := SignatureForm{Title: "New signature", New: true, Action: "/signatures"}
	src, ok := formYAML(w, r)
	if !ok {
		form.Errors = []string{errYAMLTooLarge}
		s.renderStatus(w, r, http.StatusRequestEntityTooLarge, "signature-form", form)
		return
	}
	form.YAML = src
	p, err := sig.Parse([]byte(src))
	if err == nil {
		err = s.sigStore().Create(r.Context(), p)
		if errors.Is(err, store.ErrSignatureExists) {
			err = fmt.Errorf("a signature with id %q already exists", p.ID)
		}
	}
	if err != nil {
		form.Errors = problems(err)
		s.renderStatus(w, r, http.StatusUnprocessableEntity, "signature-form", form)
		return
	}
	u, _ := auth.CurrentUser(r.Context())
	s.audit(r, &u.ID, "signature.create", "signature:"+p.ID, map[string]any{"name": p.Name})
	s.signaturesChanged()
	setFlash(w, r, "Signature "+p.ID+" saved.")
	http.Redirect(w, r, "/signatures/"+url.PathEscape(p.ID), http.StatusSeeOther)
}

func (s *Server) signatureUpdate(w http.ResponseWriter, r *http.Request) {
	row, ok := s.loadSignature(w, r)
	if !ok {
		return
	}
	if row.IsBuiltin() {
		s.builtinConflict(w, r)
		return
	}
	src, ok := formYAML(w, r)
	form := editForm(row.ID, src)
	if !ok {
		form.YAML, form.Errors = row.YAML, []string{errYAMLTooLarge}
		s.renderStatus(w, r, http.StatusRequestEntityTooLarge, "signature-form", form)
		return
	}
	p, err := sig.Parse([]byte(src))
	if err == nil && p.ID != row.ID {
		err = fmt.Errorf("the signature id cannot change (%s)", row.ID)
	}
	if err == nil {
		p.Source = row.Source
		err = s.sigStore().Update(r.Context(), row.ID, p)
	}
	if errors.Is(err, store.ErrSignatureBuiltin) {
		s.builtinConflict(w, r)
		return
	}
	if err != nil {
		form.Errors = problems(err)
		s.renderStatus(w, r, http.StatusUnprocessableEntity, "signature-form", form)
		return
	}
	u, _ := auth.CurrentUser(r.Context())
	s.audit(r, &u.ID, "signature.update", "signature:"+row.ID, map[string]any{"name": p.Name})
	s.signaturesChanged()
	setFlash(w, r, "Signature "+row.ID+" saved.")
	http.Redirect(w, r, "/signatures/"+url.PathEscape(row.ID), http.StatusSeeOther)
}

func (s *Server) signatureToggle(w http.ResponseWriter, r *http.Request) {
	row, ok := s.loadSignature(w, r)
	if !ok {
		return
	}
	if err := s.sigStore().SetEnabled(r.Context(), row.ID, !row.Enabled); err != nil {
		s.log.Error("toggle signature", "id", row.ID, "err", err)
		s.serverError(w, r)
		return
	}
	action, msg := "signature.enable", "Signature "+row.ID+" enabled."
	if row.Enabled {
		action, msg = "signature.disable", "Signature "+row.ID+" disabled."
	}
	u, _ := auth.CurrentUser(r.Context())
	s.audit(r, &u.ID, action, "signature:"+row.ID, nil)
	s.signaturesChanged()
	setFlash(w, r, msg)
	back := "/signatures"
	if r.PostFormValue("back") == "view" {
		back += "/" + url.PathEscape(row.ID)
	}
	http.Redirect(w, r, back, http.StatusSeeOther)
}

func (s *Server) signatureDelete(w http.ResponseWriter, r *http.Request) {
	row, ok := s.loadSignature(w, r)
	if !ok {
		return
	}
	if row.IsBuiltin() {
		s.builtinConflict(w, r)
		return
	}
	if err := s.sigStore().Delete(r.Context(), row.ID); err != nil {
		if errors.Is(err, store.ErrSignatureNotFound) {
			s.notFound(w, r)
			return
		}
		s.log.Error("delete signature", "id", row.ID, "err", err)
		s.serverError(w, r)
		return
	}
	u, _ := auth.CurrentUser(r.Context())
	s.audit(r, &u.ID, "signature.delete", "signature:"+row.ID, nil)
	s.signaturesChanged()
	setFlash(w, r, "Signature "+row.ID+" deleted.")
	http.Redirect(w, r, "/signatures", http.StatusSeeOther)
}

// signatureBacktest tests a stored signature (enabled or not) against the
// stored history.
func (s *Server) signatureBacktest(w http.ResponseWriter, r *http.Request) {
	row, ok := s.loadSignature(w, r)
	if !ok {
		return
	}
	p, err := sig.Parse([]byte(row.YAML))
	if err != nil {
		s.renderSignature(w, r, row, nil)
		return
	}
	bt, err := s.backtest(r.Context(), p)
	if err != nil {
		s.log.Error("backtest", "id", row.ID, "err", err)
		s.serverError(w, r)
		return
	}
	s.renderSignature(w, r, row, bt)
}

// signatureBacktestDraft tests the YAML in the form without storing it.
func (s *Server) signatureBacktestDraft(w http.ResponseWriter, r *http.Request) {
	src, ok := formYAML(w, r)
	form := SignatureForm{Title: "New signature", New: true, Action: "/signatures", YAML: src}
	if id := r.PostForm.Get("edit"); id != "" {
		form = editForm(id, src)
	}
	if !ok {
		form.Errors = []string{errYAMLTooLarge}
		s.renderStatus(w, r, http.StatusRequestEntityTooLarge, "signature-form", form)
		return
	}
	p, err := sig.Parse([]byte(src))
	if err != nil {
		form.Errors = problems(err)
		s.renderStatus(w, r, http.StatusUnprocessableEntity, "signature-form", form)
		return
	}
	if form.Backtest, err = s.backtest(r.Context(), p); err != nil {
		s.log.Error("backtest draft", "err", err)
		s.serverError(w, r)
		return
	}
	s.render(w, r, "signature-form", form)
}

// backtest evaluates p against the stored history; it sends no requests.
func (s *Server) backtest(ctx context.Context, p *sig.Signature) (*BacktestView, error) {
	hist, err := s.d.Store.BacktestHistory(ctx, backtestRuns)
	if err != nil {
		return nil, err
	}
	obs := make([]sig.Observation, len(hist))
	runs := map[int64]bool{}
	for i, h := range hist {
		obs[i] = sig.Observation{Service: h.Service, HTTP: h.HTTP}
		runs[h.Service.RunID] = true
	}
	ctx, cancel := context.WithTimeout(ctx, backtestTimeout)
	defer cancel()
	res := sig.Backtest(ctx, p, obs)
	v := &BacktestView{Runs: len(runs), Checked: res.Checked, Total: len(res.Matches),
		PathMatchers: res.PathMatchers, Stopped: res.Err != nil}
	for i, m := range res.Matches {
		if i == maxBacktestRows {
			break
		}
		v.Rows = append(v.Rows, BacktestRow{RunID: m.RunID, Asset: assetLabel(m.Key), Href: serviceHref(m.Key),
			Evidence: evidenceText(m.Detection.Evidence)})
	}
	return v, nil
}

func assetLabel(k model.AssetKey) string {
	l := k.IP.String() + ":" + strconv.Itoa(int(k.Port)) + "/" + k.Proto
	if k.VHost != "" {
		l += " (" + k.VHost + ")"
	}
	return l
}

func serviceHref(k model.AssetKey) string {
	return "/assets/" + url.PathEscape(k.IP.String()) + "/" + strconv.Itoa(int(k.Port)) + "/" + url.PathEscape(k.Proto)
}

// evidenceText renders detection evidence as sorted key=value pairs.
func evidenceText(ev map[string]string) string {
	keys := make([]string, 0, len(ev))
	for k := range ev {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = k + "=" + ev[k]
	}
	return strings.Join(parts, " · ")
}
