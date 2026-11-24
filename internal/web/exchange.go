package web

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/chrobson/ramparteye/internal/auth"
	"github.com/chrobson/ramparteye/internal/diff"
	"github.com/chrobson/ramparteye/internal/exchange"
	"github.com/chrobson/ramparteye/internal/scope"
	"github.com/chrobson/ramparteye/internal/store"
)

// Exchange imports scan results and loads run snapshots for export.
type Exchange interface {
	Import(ctx context.Context, b []byte, s scope.Scope, cfg diff.Config, now time.Time) (exchange.Report, error)
	// Snapshot loads a finished run (0 = the latest); store.ErrRunNotFound
	// when there is none.
	Snapshot(ctx context.Context, runID int64) (exchange.Snapshot, error)
}

// NewExchange returns the Exchange backed by db (the connection pool).
func NewExchange(db store.DBTX) Exchange { return dbExchange{db: db} }

type dbExchange struct{ db store.DBTX }

func (x dbExchange) Import(ctx context.Context, b []byte, s scope.Scope, cfg diff.Config, now time.Time) (exchange.Report, error) {
	return exchange.Import(ctx, x.db, b, s, cfg, now)
}

func (x dbExchange) Snapshot(ctx context.Context, runID int64) (exchange.Snapshot, error) {
	return exchange.LoadSnapshot(ctx, store.New(x.db), runID)
}

// ImportView is an import report on the page.
type ImportView struct {
	exchange.Report
	FormatLabel string
}

// ExportRun is the run offered for export.
type ExportRun struct {
	ID       int64
	Kind     string
	Date     time.Time
	Services int
	Findings int
}

// ExchangeData is the import / export page.
type ExchangeData struct {
	Title     string
	Available bool
	NoScope   bool
	MaxMB     int
	Error     string
	Report    *ImportView
	Run       *ExportRun
	// RunUnavailable: the latest run could not be loaded.
	RunUnavailable bool
}

func formatLabel(f exchange.Format) string {
	switch f {
	case exchange.FormatNmapXML:
		return "nmap XML"
	case exchange.FormatGeneric:
		return "DefectDojo Generic Findings"
	}
	return "unknown"
}

func (s *Server) exchangePage(w http.ResponseWriter, r *http.Request) {
	s.renderExchange(w, r, http.StatusOK, ExchangeData{})
}

// renderExchange fills the export part of d and renders the page.
func (s *Server) renderExchange(w http.ResponseWriter, r *http.Request, status int, d ExchangeData) {
	d.Title, d.Available, d.NoScope = "Import / export", s.d.Exchange != nil, s.d.Scope.Empty()
	d.MaxMB = exchange.MaxImportSize >> 20
	if s.d.Exchange != nil && auth.Can(r.Context(), auth.PermExport) {
		snap, err := s.d.Exchange.Snapshot(r.Context(), 0)
		switch {
		case errors.Is(err, store.ErrNotFound):
		case err != nil:
			// The page still renders: an import report must not turn into a 500.
			s.log.Error("load export snapshot", "err", err)
			d.RunUnavailable = true
		default:
			d.Run = &ExportRun{ID: snap.RunID, Kind: snap.RunKind, Date: snap.Date, Services: len(snap.Services),
				Findings: len(snap.Findings())}
		}
	}
	s.renderStatus(w, r, status, "exchange", d)
}

// exchangeImport stores an uploaded nmap XML or Generic Findings file as
// an import run.
func (s *Server) exchangeImport(w http.ResponseWriter, r *http.Request) {
	if s.d.Exchange == nil {
		s.renderExchange(w, r, http.StatusServiceUnavailable, ExchangeData{
			Error: "Importing is not available in this process."})
		return
	}
	// The file may be up to MaxImportSize; one byte more lets the parser
	// report it as too large. The overhead covers the multipart framing.
	r.Body = http.MaxBytesReader(w, r.Body, exchange.MaxImportSize+1+uploadOverhead)
	up, err := readUpload(r, "file", exchange.MaxImportSize)
	if err != nil {
		code, msg := uploadError(err, exchange.MaxImportSize, "an nmap XML or Generic Findings JSON file")
		s.renderExchange(w, r, code, ExchangeData{Error: msg})
		return
	}
	if s.d.Scope.Empty() {
		s.renderExchange(w, r, http.StatusUnprocessableEntity, ExchangeData{Error: noScopeImportMessage})
		return
	}
	ctx := r.Context()
	rep, err := s.d.Exchange.Import(ctx, up.Data, s.d.Scope, diff.Config(s.d.Cfg.Unstable), s.now())
	u, _ := auth.CurrentUser(ctx)
	s.audit(r, &u.ID, "results.import", "import", map[string]any{"format": string(rep.Format),
		"run_id": rep.RunID, "ok": err == nil, "bytes": len(up.Data), "dropped": rep.Dropped})
	v := &ImportView{Report: rep, FormatLabel: formatLabel(rep.Format)}
	switch {
	case errors.Is(err, scope.ErrNoScope):
		s.renderExchange(w, r, http.StatusUnprocessableEntity, ExchangeData{Error: noScopeImportMessage})
		return
	case errors.Is(err, exchange.ErrTooLarge):
		s.renderExchange(w, r, http.StatusRequestEntityTooLarge, ExchangeData{Error: "Import failed: " + err.Error() + "."})
		return
	case err != nil:
		s.log.Warn("import results", "err", err)
		s.renderExchange(w, r, http.StatusUnprocessableEntity, ExchangeData{Error: "Import failed: " + err.Error() + ".",
			Report: v})
		return
	}
	s.renderExchange(w, r, http.StatusOK, ExchangeData{Report: v})
}

const noScopeImportMessage = "No scan scope configured: set RAMPART_ALLOWED_CIDRS. Imports are refused until a scope is set."

// exportRunID parses ?run= (absent = 0, the latest finished run).
func exportRunID(r *http.Request) (int64, bool) {
	v := r.URL.Query().Get("run")
	if v == "" {
		return 0, true
	}
	id, err := strconv.ParseInt(v, 10, 64)
	return id, err == nil && id > 0
}

func (s *Server) exportCSV(w http.ResponseWriter, r *http.Request) {
	s.export(w, r, "csv", "text/csv; charset=utf-8", exchange.WriteCSV)
}

func (s *Server) exportJSON(w http.ResponseWriter, r *http.Request) {
	s.export(w, r, "json", "application/json", exchange.WriteJSON)
}

// export writes one run's services as an attachment. The body is built
// before any header is sent, so a failure gives a clean error page.
func (s *Server) export(w http.ResponseWriter, r *http.Request, ext, ctype string, write func(io.Writer, exchange.Snapshot) error) {
	id, ok := exportRunID(r)
	if !ok || s.d.Exchange == nil {
		s.notFound(w, r)
		return
	}
	snap, err := s.d.Exchange.Snapshot(r.Context(), id)
	switch {
	case errors.Is(err, store.ErrNotFound):
		s.notFound(w, r)
		return
	case err != nil:
		s.log.Error("load export snapshot", "run", id, "err", err)
		s.serverError(w, r)
		return
	}
	var buf bytes.Buffer
	if err := write(&buf, snap); err != nil {
		s.log.Error("write export", "run", snap.RunID, "err", err)
		s.serverError(w, r)
		return
	}
	u, _ := auth.CurrentUser(r.Context())
	s.audit(r, &u.ID, "export."+ext, "scan_run:"+strconv.FormatInt(snap.RunID, 10), nil)
	h := w.Header()
	h.Set("Content-Type", ctype)
	// The name holds only digits and fixed text: safe in the header.
	h.Set("Content-Disposition", fmt.Sprintf(`attachment; filename="ramparteye-run-%d-services.%s"`, snap.RunID, ext))
	h.Set("Cache-Control", "no-store")
	_, _ = buf.WriteTo(w)
}
