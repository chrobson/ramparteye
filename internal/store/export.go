package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/chrobson/ramparteye/internal/model"
)

// ExportRun is the finished run an export is built from.
type ExportRun struct {
	ID         int64
	Kind       string
	Status     string
	StartedAt  *time.Time
	FinishedAt *time.Time
}

// Date is the day findings are dated with: finish, start, or now (UTC).
func (r ExportRun) Date() time.Time {
	switch {
	case r.FinishedAt != nil:
		return r.FinishedAt.UTC()
	case r.StartedAt != nil:
		return r.StartedAt.UTC()
	}
	return time.Now().UTC()
}

// HTTPSummary is the HTTP part of an exported service.
type HTTPSummary struct {
	URL    string
	Status int
	Title  string
}

// ExportService is a service with its host name, HTTP summary and
// detections.
type ExportService struct {
	model.ServiceObs
	Hostname   string
	HTTP       *HTTPSummary // nil = not probed
	Detections []model.Detection
}

const exportRunCols = `id, kind, status, started_at, finished_at`

func scanExportRun(row pgx.Row) (ExportRun, error) {
	var r ExportRun
	err := row.Scan(&r.ID, &r.Kind, &r.Status, &r.StartedAt, &r.FinishedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return r, ErrRunNotFound
	}
	return r, err
}

// LatestExportRun returns the newest finished scan run, or the newest
// finished import when no scan has finished.
func (s *Store) LatestExportRun(ctx context.Context) (ExportRun, error) {
	return scanExportRun(s.db.QueryRow(ctx, `SELECT `+exportRunCols+` FROM scan_runs WHERE status = 'done'
		ORDER BY (kind = 'scan') DESC, coalesce(finished_at, started_at) DESC NULLS LAST, id DESC LIMIT 1`))
}

// ExportRunByID returns one finished run.
func (s *Store) ExportRunByID(ctx context.Context, id int64) (ExportRun, error) {
	return scanExportRun(s.db.QueryRow(ctx, `SELECT `+exportRunCols+` FROM scan_runs
		WHERE id = $1 AND status = 'done'`, id))
}

// ExportServices loads every service of a run with host name, HTTP summary
// and detections, ordered by address, port, protocol and virtual host.
func (s *Store) ExportServices(ctx context.Context, runID int64) ([]ExportService, error) {
	rows, err := s.db.Query(ctx, `
		SELECT s.id, host(s.ip), s.port, s.proto, s.vhost, s.product, s.version,
		       s.extrainfo, s.cpe, s.banner, coalesce(h.hostname, ''),
		       ho.url, ho.status, coalesce(ho.title, '')
		FROM services s
		LEFT JOIN host_obs h ON h.run_id = s.run_id AND h.ip = s.ip
		LEFT JOIN http_obs ho ON ho.service_id = s.id
		WHERE s.run_id = $1
		ORDER BY s.ip, s.port, s.proto, s.vhost`, runID)
	if err != nil {
		return nil, err
	}
	out, err := collect(rows, func(r pgx.Rows) (ExportService, error) {
		var (
			sv     ExportService
			ip     string
			port   int
			url    *string
			status *int
			title  string
		)
		if err := r.Scan(&sv.ID, &ip, &port, &sv.Key.Proto, &sv.Key.VHost, &sv.Product, &sv.Version,
			&sv.ExtraInfo, &sv.CPE, &sv.Banner, &sv.Hostname, &url, &status, &title); err != nil {
			return sv, err
		}
		sv.RunID = runID
		sv.Key.Port = uint16(port)
		if url != nil {
			sv.HTTP = &HTTPSummary{URL: *url, Title: title}
			if status != nil {
				sv.HTTP.Status = *status
			}
		}
		var err error
		sv.Key.IP, err = parseAddr(ip)
		return sv, err
	})
	if err != nil {
		return nil, err
	}

	drows, err := s.db.Query(ctx, `
		SELECT d.service_id, d.signature_id, d.name, d.category, d.confidence, d.evidence
		FROM detections d JOIN services s ON s.id = d.service_id
		WHERE s.run_id = $1 ORDER BY d.service_id, d.signature_id`, runID)
	if err != nil {
		return nil, err
	}
	dets, err := collect(drows, scanDetection)
	if err != nil {
		return nil, err
	}
	index := make(map[int64]int, len(out))
	for i, sv := range out {
		index[sv.ID] = i
	}
	for _, d := range dets {
		if i, ok := index[d.ServiceID]; ok {
			out[i].Detections = append(out[i].Detections, d)
		}
	}
	return out, nil
}
