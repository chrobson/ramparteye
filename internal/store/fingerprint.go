package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/chrobson/ramparteye/internal/model"
)

// LegacyTLS is the result of the explicit TLS 1.0 / 1.1 handshake probe.
type LegacyTLS struct {
	TLS10, TLS11             bool
	TLS10Cipher, TLS11Cipher string
}

// SaveHTTPObs upserts the HTTP observation of a service. The body is never
// stored, only its SHA-256; a zero Status or ResponseMS is stored as NULL.
func (s *Store) SaveHTTPObs(ctx context.Context, o model.HTTPObs) error {
	headers, err := json.Marshal(nonNilMap(o.Headers))
	if err != nil {
		return err
	}
	cookies, err := json.Marshal(nonNilSlice(o.Cookies))
	if err != nil {
		return err
	}
	redirects, err := json.Marshal(nonNilSlice(o.Redirects))
	if err != nil {
		return err
	}
	var tlsJSON []byte
	if o.TLS != nil {
		if tlsJSON, err = json.Marshal(o.TLS); err != nil {
			return err
		}
	}
	var status, responseMS *int
	if o.Status != 0 {
		status = &o.Status
	}
	if o.ResponseMS > 0 {
		responseMS = &o.ResponseMS
	}
	_, err = s.db.Exec(ctx, `
		INSERT INTO http_obs (service_id, url, status, title, headers, cookies, redirects, tls,
			favicon_mmh3, body_sha256, response_ms)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		ON CONFLICT (service_id) DO UPDATE SET
			url = EXCLUDED.url, status = EXCLUDED.status, title = EXCLUDED.title,
			headers = EXCLUDED.headers, cookies = EXCLUDED.cookies, redirects = EXCLUDED.redirects,
			tls = EXCLUDED.tls, favicon_mmh3 = EXCLUDED.favicon_mmh3, body_sha256 = EXCLUDED.body_sha256,
			response_ms = EXCLUDED.response_ms`,
		o.ServiceID, o.URL, status, o.Title, headers, cookies, redirects, tlsJSON, o.FaviconMMH3,
		o.BodySHA256, responseMS)
	return err
}

// HTTPObs loads the stored observation of a service (Body is always nil).
func (s *Store) HTTPObs(ctx context.Context, serviceID int64) (model.HTTPObs, error) {
	o := model.HTTPObs{ServiceID: serviceID}
	var status, responseMS *int
	var headers, cookies, redirects, tlsJSON []byte
	err := s.db.QueryRow(ctx, `SELECT url, status, title, headers, cookies, redirects, tls, favicon_mmh3,
		body_sha256, response_ms FROM http_obs WHERE service_id = $1`, serviceID).
		Scan(&o.URL, &status, &o.Title, &headers, &cookies, &redirects, &tlsJSON, &o.FaviconMMH3,
			&o.BodySHA256, &responseMS)
	if errors.Is(err, pgx.ErrNoRows) {
		return o, fmt.Errorf("http observation of service %d: %w", serviceID, ErrNotFound)
	}
	if err != nil {
		return o, err
	}
	return o, decodeHTTPObs(&o, status, responseMS, headers, cookies, redirects, tlsJSON)
}

// decodeHTTPObs fills the nullable and JSON columns of an http_obs row.
func decodeHTTPObs(o *model.HTTPObs, status, responseMS *int, headers, cookies, redirects, tlsJSON []byte) error {
	if status != nil {
		o.Status = *status
	}
	if responseMS != nil {
		o.ResponseMS = *responseMS
	}
	if err := json.Unmarshal(headers, &o.Headers); err != nil {
		return fmt.Errorf("headers: %w", err)
	}
	if err := json.Unmarshal(cookies, &o.Cookies); err != nil {
		return fmt.Errorf("cookies: %w", err)
	}
	if err := json.Unmarshal(redirects, &o.Redirects); err != nil {
		return fmt.Errorf("redirects: %w", err)
	}
	if len(tlsJSON) > 0 {
		o.TLS = &model.TLSInfo{}
		if err := json.Unmarshal(tlsJSON, o.TLS); err != nil {
			return fmt.Errorf("tls: %w", err)
		}
	}
	return nil
}

// ReplaceDetections replaces every detection of a service.
func (s *Store) ReplaceDetections(ctx context.Context, serviceID int64, ds []model.Detection) error {
	return s.InTx(ctx, func(tx *Store) error {
		if _, err := tx.db.Exec(ctx, `DELETE FROM detections WHERE service_id = $1`, serviceID); err != nil {
			return err
		}
		for _, d := range ds {
			d.ServiceID = serviceID
			if err := tx.upsertDetection(ctx, d); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *Store) upsertDetection(ctx context.Context, d model.Detection) error {
	ev, err := json.Marshal(nonNilMap(d.Evidence))
	if err != nil {
		return err
	}
	_, err = s.db.Exec(ctx, `
		INSERT INTO detections (service_id, signature_id, name, category, confidence, evidence)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (service_id, signature_id) DO UPDATE SET
			name = EXCLUDED.name, category = EXCLUDED.category,
			confidence = EXCLUDED.confidence, evidence = EXCLUDED.evidence`,
		d.ServiceID, d.SignatureID, d.Name, d.Category, d.Confidence, ev)
	return err
}

// Detections returns the detections of a service, most confident first.
func (s *Store) Detections(ctx context.Context, serviceID int64) ([]model.Detection, error) {
	rows, err := s.db.Query(ctx, `SELECT service_id, signature_id, name, category, confidence, evidence
		FROM detections WHERE service_id = $1 ORDER BY confidence DESC, signature_id`, serviceID)
	if err != nil {
		return nil, err
	}
	return collect(rows, scanDetection)
}

func scanDetection(r pgx.Rows) (model.Detection, error) {
	var d model.Detection
	var ev []byte
	if err := r.Scan(&d.ServiceID, &d.SignatureID, &d.Name, &d.Category, &d.Confidence, &ev); err != nil {
		return d, err
	}
	d.Evidence = evidenceMap(ev)
	return d, nil
}

// evidenceMap reads a jsonb evidence object; non-string values are kept as
// their JSON text.
func evidenceMap(b []byte) map[string]string {
	var raw map[string]any
	if err := json.Unmarshal(b, &raw); err != nil || len(raw) == 0 {
		return nil
	}
	out := make(map[string]string, len(raw))
	for k, v := range raw {
		if s, ok := v.(string); ok {
			out[k] = s
			continue
		}
		j, _ := json.Marshal(v)
		out[k] = string(j)
	}
	return out
}

// SaveLegacyTLS upserts the TLS 1.0/1.1 probe result of a service.
func (s *Store) SaveLegacyTLS(ctx context.Context, serviceID int64, r LegacyTLS) error {
	_, err := s.db.Exec(ctx, `
		INSERT INTO tls_legacy (service_id, tls10, tls11, tls10_cipher, tls11_cipher, probed_at)
		VALUES ($1, $2, $3, $4, $5, now())
		ON CONFLICT (service_id) DO UPDATE SET
			tls10 = EXCLUDED.tls10, tls11 = EXCLUDED.tls11,
			tls10_cipher = EXCLUDED.tls10_cipher, tls11_cipher = EXCLUDED.tls11_cipher,
			probed_at = EXCLUDED.probed_at`,
		serviceID, r.TLS10, r.TLS11, r.TLS10Cipher, r.TLS11Cipher)
	return err
}

// LegacyTLS loads the TLS 1.0/1.1 probe result of a service; ErrNotFound
// when it was never probed.
func (s *Store) LegacyTLS(ctx context.Context, serviceID int64) (LegacyTLS, error) {
	var r LegacyTLS
	err := s.db.QueryRow(ctx, `SELECT tls10, tls11, tls10_cipher, tls11_cipher FROM tls_legacy
		WHERE service_id = $1`, serviceID).Scan(&r.TLS10, &r.TLS11, &r.TLS10Cipher, &r.TLS11Cipher)
	if errors.Is(err, pgx.ErrNoRows) {
		return r, fmt.Errorf("legacy TLS probe of service %d: %w", serviceID, ErrNotFound)
	}
	return r, err
}
