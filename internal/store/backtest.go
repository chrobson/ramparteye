package store

import (
	"context"

	"github.com/jackc/pgx/v5"

	"github.com/chrobson/ramparteye/internal/model"
)

// ObservedService is a stored service observation with its HTTP
// fingerprint (zero HTTP when the service was not probed; Body is nil).
type ObservedService struct {
	Service model.ServiceObs
	HTTP    model.HTTPObs
}

// BacktestHistory returns every service of the newest lastRuns finished
// scan runs with its HTTP observation, newest run first, for testing a
// signature against history without sending requests.
func (s *Store) BacktestHistory(ctx context.Context, lastRuns int) ([]ObservedService, error) {
	rows, err := s.db.Query(ctx, `
		WITH r AS (`+lastScanRuns+`)
		SELECT s.id, s.run_id, host(s.ip), s.port, s.proto, s.vhost, s.product, s.version,
		       s.extrainfo, s.cpe, s.banner,
		       ho.url, ho.status, coalesce(ho.title, ''), coalesce(ho.headers, '{}'), coalesce(ho.cookies, '[]'),
		       coalesce(ho.redirects, '[]'), ho.tls, ho.favicon_mmh3, coalesce(ho.body_sha256, ''), ho.response_ms
		FROM services s JOIN r ON r.id = s.run_id
		LEFT JOIN http_obs ho ON ho.service_id = s.id
		ORDER BY s.run_id DESC, s.ip, s.port, s.proto, s.vhost`, lastRuns)
	if err != nil {
		return nil, err
	}
	return collect(rows, func(r pgx.Rows) (ObservedService, error) {
		var (
			o                                    ObservedService
			ip                                   string
			port                                 int
			url                                  *string
			status, responseMS                   *int
			headers, cookies, redirects, tlsJSON []byte
			sv                                   = &o.Service
			h                                    = &o.HTTP
		)
		if err := r.Scan(&sv.ID, &sv.RunID, &ip, &port, &sv.Key.Proto, &sv.Key.VHost, &sv.Product,
			&sv.Version, &sv.ExtraInfo, &sv.CPE, &sv.Banner, &url, &status, &h.Title, &headers, &cookies,
			&redirects, &tlsJSON, &h.FaviconMMH3, &h.BodySHA256, &responseMS); err != nil {
			return o, err
		}
		sv.Key.Port = uint16(port)
		var err error
		if sv.Key.IP, err = parseAddr(ip); err != nil {
			return o, err
		}
		if url == nil {
			o.HTTP = model.HTTPObs{}
			return o, nil
		}
		h.ServiceID, h.URL = sv.ID, *url
		return o, decodeHTTPObs(h, status, responseMS, headers, cookies, redirects, tlsJSON)
	})
}
