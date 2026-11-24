package store

import (
	"context"
	"encoding/json"

	"github.com/jackc/pgx/v5"

	"github.com/chrobson/ramparteye/internal/model"
)

// InsertObservations writes the host and service observations of a run. It
// is idempotent per natural key, so overlapping chunks cannot fail a run: a
// host seen up stays up and keeps its first hostname, a service takes the
// latest fields.
func (s *Store) InsertObservations(ctx context.Context, runID int64, hosts []model.HostObs, svcs []model.ServiceObs) error {
	b := &pgx.Batch{}
	for _, h := range hosts {
		b.Queue(`INSERT INTO host_obs (run_id, ip, hostname, up) VALUES ($1, $2::inet, $3, $4)
			ON CONFLICT (run_id, ip) DO UPDATE SET up = host_obs.up OR EXCLUDED.up,
			hostname = CASE WHEN host_obs.hostname = '' THEN EXCLUDED.hostname ELSE host_obs.hostname END`,
			runID, h.IP.Unmap().String(), h.Hostname, h.Up)
	}
	for _, sv := range svcs {
		b.Queue(`INSERT INTO services (run_id, ip, port, proto, vhost, product, version, extrainfo, cpe, banner)
			VALUES ($1, $2::inet, $3, $4, $5, $6, $7, $8, $9, $10)
			ON CONFLICT (run_id, ip, port, proto, vhost) DO UPDATE SET product = EXCLUDED.product,
			version = EXCLUDED.version, extrainfo = EXCLUDED.extrainfo, cpe = EXCLUDED.cpe, banner = EXCLUDED.banner`,
			runID, sv.Key.IP.Unmap().String(), int(sv.Key.Port), sv.Key.Proto, sv.Key.VHost,
			sv.Product, sv.Version, sv.ExtraInfo, sv.CPE, sv.Banner)
	}
	if b.Len() == 0 {
		return nil
	}
	return s.db.SendBatch(ctx, b).Close()
}

// BeginImportRun creates a running run of kind import. Call the Import*
// methods inside the same InTx so a failed import leaves nothing behind.
func (s *Store) BeginImportRun(ctx context.Context) (int64, error) {
	var id int64
	err := s.db.QueryRow(ctx, `INSERT INTO scan_runs (kind, status, started_at)
		VALUES ('import', 'running', now()) RETURNING id`).Scan(&id)
	return id, err
}

// FinishImportRun marks an import run done.
func (s *Store) FinishImportRun(ctx context.Context, runID int64) error {
	_, err := s.db.Exec(ctx, `UPDATE scan_runs SET status = 'done', finished_at = now(),
		duration_ms = (extract(epoch FROM (now() - started_at)) * 1000)::bigint
		WHERE id = $1`, runID)
	return err
}

// ImportHost records a host of an import; a repeated host keeps its first
// non-empty hostname and stays up once seen up.
func (s *Store) ImportHost(ctx context.Context, runID int64, h model.HostObs) error {
	return s.InsertObservations(ctx, runID, []model.HostObs{h}, nil)
}

// ImportService upserts a service of an import run and returns its id.
// Non-empty fields of an earlier record win; a later one fills the gaps.
func (s *Store) ImportService(ctx context.Context, runID int64, sv model.ServiceObs) (int64, error) {
	var id int64
	err := s.db.QueryRow(ctx, `INSERT INTO services
		(run_id, ip, port, proto, vhost, product, version, extrainfo, cpe, banner)
		VALUES ($1, $2::inet, $3, $4, $5, $6, $7, $8, $9, $10)
		ON CONFLICT (run_id, ip, port, proto, vhost) DO UPDATE SET
			product   = coalesce(nullif(services.product, ''), EXCLUDED.product),
			version   = coalesce(nullif(services.version, ''), EXCLUDED.version),
			extrainfo = coalesce(nullif(services.extrainfo, ''), EXCLUDED.extrainfo),
			cpe       = coalesce(nullif(services.cpe, ''), EXCLUDED.cpe),
			banner    = coalesce(nullif(services.banner, ''), EXCLUDED.banner)
		RETURNING id`,
		runID, sv.Key.IP.Unmap().String(), int(sv.Key.Port), sv.Key.Proto, sv.Key.VHost,
		sv.Product, sv.Version, sv.ExtraInfo, sv.CPE, sv.Banner).Scan(&id)
	return id, err
}

// ImportDetection records a detection of an imported service; duplicates
// are ignored.
func (s *Store) ImportDetection(ctx context.Context, d model.Detection) error {
	ev, err := json.Marshal(nonNilMap(d.Evidence))
	if err != nil {
		return err
	}
	_, err = s.db.Exec(ctx, `INSERT INTO detections
		(service_id, signature_id, name, category, confidence, evidence)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (service_id, signature_id) DO NOTHING`,
		d.ServiceID, d.SignatureID, d.Name, d.Category, d.Confidence, ev)
	return err
}
