package web

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"path"
	"strconv"
	"strings"

	"github.com/chrobson/ramparteye/internal/auth"
	"github.com/chrobson/ramparteye/internal/model"
	"github.com/chrobson/ramparteye/internal/store"
	"github.com/chrobson/ramparteye/internal/target"
)

// maxRefusedShown bounds the refused rows listed in an import report.
const maxRefusedShown = 200

const noScopeMessage = "No scan scope configured: set RAMPART_ALLOWED_CIDRS. Target imports and scans are refused until a scope is set."

var targetKindLabels = map[model.TargetKind]string{
	model.TargetIP: "IP address", model.TargetCIDR: "CIDR", model.TargetRange: "range", model.TargetDomain: "domain",
}

// TargetRow is a target on the list.
type TargetRow struct {
	ID       int64
	Value    string
	Kind     string
	Addrs    string
	Tags     []string
	TagsText string // "a;b" for the edit field
}

// TargetCounts summarises the listed targets.
type TargetCounts struct {
	IP, CIDR, Range, Domain int
	Addrs                   string
}

// TargetReport is the outcome of adding or importing targets.
type TargetReport struct {
	Source       string
	Added        int
	Present      int // in scope but already stored
	Refused      []RefusedTarget
	RefusedTotal int
}

// RefusedTarget is an input row that was not stored.
type RefusedTarget struct {
	Line   int // 0 = unknown
	Value  string
	Reason string
}

func (rep *TargetReport) refuse(line int, value, reason string) {
	rep.RefusedTotal++
	if len(rep.Refused) < maxRefusedShown {
		rep.Refused = append(rep.Refused, RefusedTarget{Line: line, Value: value, Reason: reason})
	}
}

// TargetsData is the targets page.
type TargetsData struct {
	Title    string
	Targets  []TargetRow
	Tags     []string
	Filter   string
	Counts   TargetCounts
	Scope    []string
	Excluded []string
	Report   *TargetReport
	Error    string
	Values   string // the add form, kept after a rejected submission
}

// parseTagFilter validates ?tag=: empty or one valid tag.
func parseTagFilter(v string) (string, bool) {
	v = strings.TrimSpace(v)
	if v == "" {
		return "", true
	}
	tags, err := target.NormalizeTags([]string{v})
	if err != nil || len(tags) != 1 {
		return "", false
	}
	return tags[0], true
}

func (s *Server) targetsPage(w http.ResponseWriter, r *http.Request) {
	filter, ok := parseTagFilter(r.URL.Query().Get("tag"))
	if !ok {
		s.renderError(w, r, errorData{Code: http.StatusBadRequest, Title: "Invalid filter",
			Text: "The tag filter is not a valid tag. Clear the filter and try again."})
		return
	}
	s.renderTargets(w, r, http.StatusOK, TargetsData{Filter: filter})
}

// renderTargets fills the list, tags and scope banner of d and renders it.
func (s *Server) renderTargets(w http.ResponseWriter, r *http.Request, status int, d TargetsData) {
	ctx := r.Context()
	ts, err := s.d.Store.Targets(ctx, d.Filter)
	if err != nil {
		s.log.Error("list targets", "err", err)
		s.serverError(w, r)
		return
	}
	if d.Tags, err = s.d.Store.TargetTags(ctx); err != nil {
		s.log.Error("list target tags", "err", err)
		s.serverError(w, r)
		return
	}
	d.Title = "Targets"
	var total uint64
	for _, t := range ts {
		n := targetAddrs(t)
		switch t.Kind {
		case model.TargetIP:
			d.Counts.IP++
		case model.TargetCIDR:
			d.Counts.CIDR++
		case model.TargetRange:
			d.Counts.Range++
		case model.TargetDomain:
			d.Counts.Domain++
		}
		row := TargetRow{ID: t.ID, Value: t.Value, Kind: targetKindLabels[t.Kind], Tags: t.Tags,
			TagsText: strings.Join(t.Tags, ";"), Addrs: "–"}
		if t.Kind != model.TargetDomain {
			total = satAdd(total, n)
			row.Addrs = addrCount(n)
		}
		d.Targets = append(d.Targets, row)
	}
	d.Counts.Addrs = addrCount(total)
	for _, p := range s.d.Scope.Allowed() {
		d.Scope = append(d.Scope, p.String())
	}
	for _, a := range s.d.Scope.Excluded() {
		d.Excluded = append(d.Excluded, a.String())
	}
	s.renderStatus(w, r, status, "targets", d)
}

func addrCount(n uint64) string {
	if n > maxAddrsShown {
		return "more than " + num(int(maxAddrsShown))
	}
	return num(int(n))
}

// targetsAdd adds the targets typed into the form: one per line, optional
// tags after a space ("10.20.0.0/24 lab;web"), plus tags for all.
func (s *Server) targetsAdd(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, target.MaxImportBytes+maxFormBytes)
	if err := r.ParseForm(); err != nil {
		s.renderTargets(w, r, http.StatusRequestEntityTooLarge, TargetsData{
			Error: fmt.Sprintf("The list could not be read (at most %d MiB).", target.MaxImportBytes>>20)})
		return
	}
	values := r.PostForm.Get("values")
	if s.d.Scope.Empty() {
		s.renderTargets(w, r, http.StatusUnprocessableEntity, TargetsData{Error: noScopeMessage, Values: values})
		return
	}
	common := target.SplitTags(r.PostForm.Get("tags"))
	if _, err := target.NormalizeTags(common); err != nil {
		s.renderTargets(w, r, http.StatusUnprocessableEntity, TargetsData{Error: "Tags: " + err.Error() + ".",
			Values: values})
		return
	}
	rep := &TargetReport{Source: "form"}
	var (
		ts    []model.Target
		lines []int
		index = map[string]int{}
	)
	for i, line := range strings.Split(values, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || strings.HasPrefix(fields[0], "#") {
			continue
		}
		if len(ts)+rep.RefusedTotal >= target.MaxImportEntries {
			s.renderTargets(w, r, http.StatusUnprocessableEntity, TargetsData{Error: "Too many entries: at most " +
				strconv.Itoa(target.MaxImportEntries) + " per submission.", Values: values})
			return
		}
		t, err := target.Parse(fields[0])
		var tags []string
		for _, f := range fields[1:] {
			tags = append(tags, target.SplitTags(f)...)
		}
		if err == nil {
			t.Tags, err = target.NormalizeTags(append(tags, common...))
		}
		if err != nil {
			rep.refuse(i+1, strings.TrimSpace(line), err.Error())
			continue
		}
		if j, ok := index[t.Value]; ok {
			ts[j].Tags, _ = target.NormalizeTags(append(ts[j].Tags, t.Tags...))
			continue
		}
		index[t.Value] = len(ts)
		ts = append(ts, t)
		lines = append(lines, i+1)
	}
	if len(ts) == 0 && rep.RefusedTotal == 0 {
		s.renderTargets(w, r, http.StatusUnprocessableEntity, TargetsData{Error: "Enter at least one target."})
		return
	}
	s.storeTargets(w, r, "targets.add", ts, lines, rep)
}

// targetsImport imports an uploaded CSV ("value,tags") or JSON
// ([{"value": ..., "tags": [...]}]) file.
func (s *Server) targetsImport(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, target.MaxImportBytes+uploadOverhead)
	up, err := readUpload(r, "file", target.MaxImportBytes)
	if err != nil {
		code, msg := uploadError(err, target.MaxImportBytes, "a CSV or JSON file")
		s.renderTargets(w, r, code, TargetsData{Error: msg})
		return
	}
	if s.d.Scope.Empty() {
		s.renderTargets(w, r, http.StatusUnprocessableEntity, TargetsData{Error: noScopeMessage})
		return
	}
	var ts []model.Target
	if isJSONUpload(up.Name, up.Data) {
		ts, err = target.ImportJSON(bytes.NewReader(up.Data))
	} else {
		ts, err = target.ImportCSV(bytes.NewReader(up.Data))
	}
	if err != nil {
		s.renderTargets(w, r, http.StatusUnprocessableEntity, TargetsData{
			Error: "The file could not be imported, nothing was stored: " + err.Error() + "."})
		return
	}
	if extra := target.SplitTags(up.Fields["tags"]); len(extra) > 0 {
		for i := range ts {
			if ts[i].Tags, err = target.NormalizeTags(append(ts[i].Tags, extra...)); err != nil {
				s.renderTargets(w, r, http.StatusUnprocessableEntity, TargetsData{Error: "Tags: " + err.Error() + "."})
				return
			}
		}
	}
	s.storeTargets(w, r, "targets.import", ts, nil, &TargetReport{Source: path.Base(up.Name)})
}

func isJSONUpload(name string, data []byte) bool {
	if strings.HasSuffix(strings.ToLower(name), ".json") {
		return true
	}
	t := bytes.TrimLeft(bytes.TrimPrefix(data, []byte("\xef\xbb\xbf")), " \t\r\n")
	return len(t) > 0 && t[0] == '['
}

// storeTargets checks every target against the scope (domains are
// resolved, every address must be allowed), stores those inside and lists
// the rest as refused. lines are the source lines of ts when known.
func (s *Server) storeTargets(w http.ResponseWriter, r *http.Request, action string, ts []model.Target, lines []int, rep *TargetReport) {
	ctx := r.Context()
	var ok []model.Target
	for i, t := range ts {
		line := 0
		if i < len(lines) {
			line = lines[i]
		}
		if err := s.checkTarget(ctx, t); err != nil {
			rep.refuse(line, t.Value, err.Error())
			continue
		}
		ok = append(ok, t)
	}
	u, _ := auth.CurrentUser(ctx)
	n, err := s.d.Store.InsertTargets(ctx, ok, &u.ID)
	if err != nil {
		s.log.Error("insert targets", "err", err)
		s.serverError(w, r)
		return
	}
	rep.Added, rep.Present = n, len(ok)-n
	s.audit(r, &u.ID, action, "targets", map[string]any{"source": rep.Source, "added": rep.Added,
		"present": rep.Present, "refused": rep.RefusedTotal})
	s.renderTargets(w, r, http.StatusOK, TargetsData{Report: rep})
}

func (s *Server) checkTarget(ctx context.Context, t model.Target) error {
	_, err := target.Resolve(ctx, t, s.d.Resolver, s.d.Scope)
	return err
}

// targetTags replaces the tags of a target.
func (s *Server) targetTags(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r, "id")
	if !ok {
		s.notFound(w, r)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	if err := r.ParseForm(); err != nil {
		s.renderError(w, r, errorData{Code: http.StatusBadRequest, Title: "Invalid form",
			Text: "The form could not be read."})
		return
	}
	tags, err := target.NormalizeTags(target.SplitTags(r.PostForm.Get("tags")))
	if err != nil {
		setFlash(w, r, "Tags not saved: "+err.Error()+".")
		http.Redirect(w, r, "/targets", http.StatusSeeOther)
		return
	}
	switch err := s.d.Store.UpdateTargetTags(r.Context(), id, tags); {
	case errors.Is(err, store.ErrNotFound):
		s.notFound(w, r)
		return
	case err != nil:
		s.log.Error("update target tags", "id", id, "err", err)
		s.serverError(w, r)
		return
	}
	u, _ := auth.CurrentUser(r.Context())
	s.audit(r, &u.ID, "targets.tags", "target:"+strconv.FormatInt(id, 10), map[string]any{"tags": tags})
	setFlash(w, r, "Tags saved.")
	http.Redirect(w, r, "/targets", http.StatusSeeOther)
}

func (s *Server) targetDelete(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r, "id")
	if !ok {
		s.notFound(w, r)
		return
	}
	value, err := s.d.Store.DeleteTarget(r.Context(), id)
	switch {
	case errors.Is(err, store.ErrNotFound):
		s.notFound(w, r)
		return
	case err != nil:
		s.log.Error("delete target", "id", id, "err", err)
		s.serverError(w, r)
		return
	}
	u, _ := auth.CurrentUser(r.Context())
	s.audit(r, &u.ID, "targets.delete", "target:"+strconv.FormatInt(id, 10), map[string]any{"value": value})
	setFlash(w, r, "Target "+value+" deleted.")
	http.Redirect(w, r, "/targets", http.StatusSeeOther)
}
