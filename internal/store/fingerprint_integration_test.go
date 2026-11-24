//go:build integration

package store_test

import (
	"testing"
	"time"

	"github.com/ctx42/testing/pkg/assert"
	"github.com/ctx42/testing/pkg/must"

	"github.com/chrobson/ramparteye/internal/model"
	"github.com/chrobson/ramparteye/internal/store"
)

func TestHTTPObs(t *testing.T) {
	s, pool := newStore(t)
	svcID := insertService(t, pool, insertRun(t, pool, "scan", "done"), "10.20.1.5", 443)
	fav := int32(-1234)
	obs := model.HTTPObs{
		ServiceID: svcID, URL: "https://10.20.1.5/", Status: 200, Title: "Panel",
		Headers:   map[string][]string{"Server": {"nginx"}},
		Cookies:   []model.Cookie{{Name: "sid", Secure: true}},
		Redirects: []model.Redirect{{URL: "http://10.20.1.5/", Status: 301}},
		TLS: &model.TLSInfo{Subject: "CN=x", SelfSigned: true, SANs: []string{},
			NotAfter: time.Unix(1700000000, 0).UTC(), NotBefore: time.Unix(1600000000, 0).UTC()},
		FaviconMMH3: &fav, BodySHA256: "ab", Body: []byte("never stored"), ResponseMS: 640,
	}
	assert.NoError(t, s.SaveHTTPObs(ctx, obs))
	obs.Title = "Panel 2"
	assert.NoError(t, s.SaveHTTPObs(ctx, obs)) // upsert

	got := must.Value(s.HTTPObs(ctx, svcID))
	obs.Body = nil
	assert.Equal(t, obs, got)

	obs.ResponseMS, obs.Status, obs.TLS = 0, 0, nil // not measured: stored as NULL
	assert.NoError(t, s.SaveHTTPObs(ctx, obs))
	var nullMS, nullStatus bool
	must.Nil(pool.QueryRow(ctx, `SELECT response_ms IS NULL, status IS NULL FROM http_obs WHERE service_id = $1`,
		svcID).Scan(&nullMS, &nullStatus))
	assert.True(t, nullMS)
	assert.True(t, nullStatus)
	assert.Nil(t, must.Value(s.HTTPObs(ctx, svcID)).TLS)

	_, err := s.HTTPObs(ctx, -1)
	assert.ErrorIs(t, store.ErrNotFound, err)
}

func TestDetectionsAndLegacyTLS(t *testing.T) {
	s, pool := newStore(t)
	svcID := insertService(t, pool, insertRun(t, pool, "scan", "done"), "10.20.1.5", 443)
	ds := []model.Detection{
		{SignatureID: "nginx", Name: "nginx", Category: "server", Confidence: 85, Evidence: map[string]string{"version": "1.25"}},
		{SignatureID: "wp", Name: "WordPress", Category: "cms", Confidence: 95},
	}
	assert.NoError(t, s.ReplaceDetections(ctx, svcID, ds))
	assert.NoError(t, s.ReplaceDetections(ctx, svcID, ds[:1]))

	list := must.Value(s.Detections(ctx, svcID))
	assert.Len(t, 1, list)
	assert.Equal(t, "1.25", list[0].Evidence["version"])
	assert.Equal(t, svcID, list[0].ServiceID)

	_, err := s.LegacyTLS(ctx, svcID)
	assert.ErrorIs(t, store.ErrNotFound, err)
	in := store.LegacyTLS{TLS10: true, TLS10Cipher: "TLS_RSA_WITH_AES_128_CBC_SHA"}
	assert.NoError(t, s.SaveLegacyTLS(ctx, svcID, in))
	assert.Equal(t, in, must.Value(s.LegacyTLS(ctx, svcID)))
}

func TestSignatures(t *testing.T) {
	s, _ := newStore(t)
	builtin := []store.SignatureRow{
		{ID: "nginx", Name: "nginx", YAML: "id: nginx"},
		{ID: "wordpress", Name: "WP", YAML: "id: wordpress", PathProbe: true},
	}
	assert.NoError(t, s.SyncBuiltinSignatures(ctx, builtin))
	assert.NoError(t, s.SetSignatureEnabled(ctx, "nginx", false))
	builtin[0].YAML = "id: nginx\n# v2"
	builtin[0].PathProbe = true
	assert.NoError(t, s.SyncBuiltinSignatures(ctx, builtin)) // keeps enabled=false, updates YAML

	r := must.Value(s.Signature(ctx, "nginx"))
	assert.False(t, r.Enabled)
	assert.Equal(t, store.SourceBuiltin, r.Source)
	assert.True(t, r.IsBuiltin())
	assert.True(t, r.PathProbe)
	assert.Equal(t, "id: nginx\n# v2", r.YAML)

	custom := store.SignatureRow{ID: "zz-custom", Name: "C", YAML: "id: zz-custom", Enabled: true}
	assert.NoError(t, s.CreateCustomSignature(ctx, custom))
	assert.ErrorIs(t, store.ErrSignatureExists, s.CreateCustomSignature(ctx, custom))
	got := must.Value(s.Signature(ctx, "zz-custom"))
	assert.Equal(t, store.SourceCustom, got.Source)
	assert.True(t, got.Enabled)
	assert.False(t, got.IsBuiltin())

	// A nuclei import is stored disabled, for review, with its probe flag.
	nuclei := store.SignatureRow{ID: "nuc-status", Name: "N", YAML: "id: nuc-status", Source: store.SourceNuclei, PathProbe: true}
	assert.NoError(t, s.CreateCustomSignature(ctx, nuclei))
	got = must.Value(s.Signature(ctx, "nuc-status"))
	assert.Equal(t, store.SourceNuclei, got.Source)
	assert.False(t, got.Enabled)
	assert.True(t, got.PathProbe)

	// A custom signature cannot claim to be built in.
	err := s.CreateCustomSignature(ctx, store.SignatureRow{ID: "fake", Name: "F", YAML: "id: fake", Source: store.SourceBuiltin})
	assert.ErrorIs(t, store.ErrSignatureBuiltin, err)
	_, err = s.Signature(ctx, "fake")
	assert.ErrorIs(t, store.ErrSignatureNotFound, err)

	assert.ErrorIs(t, store.ErrSignatureBuiltin, s.UpdateCustomSignature(ctx, "nginx", store.SignatureRow{ID: "nginx"}))
	assert.ErrorIs(t, store.ErrSignatureBuiltin, s.DeleteCustomSignature(ctx, "wordpress"))
	assert.Error(t, s.UpdateCustomSignature(ctx, "zz-custom", store.SignatureRow{ID: "other"}))
	custom.Name = "C2"
	custom.PathProbe = true
	assert.NoError(t, s.UpdateCustomSignature(ctx, "zz-custom", custom))
	got = must.Value(s.Signature(ctx, "zz-custom"))
	assert.Equal(t, "C2", got.Name)
	assert.True(t, got.PathProbe)
	assert.Equal(t, store.SourceCustom, got.Source)

	all := must.Value(s.Signatures(ctx))
	assert.Len(t, 4, all)
	assert.Equal(t, "nginx", all[0].ID) // built-ins first
	assert.Equal(t, "wordpress", all[1].ID)
	assert.Equal(t, "nuc-status", all[2].ID)
	assert.Equal(t, "zz-custom", all[3].ID)

	assert.NoError(t, s.DeleteCustomSignature(ctx, "zz-custom"))
	_, err = s.Signature(ctx, "zz-custom")
	assert.ErrorIs(t, store.ErrSignatureNotFound, err)
	assert.ErrorIs(t, store.ErrSignatureNotFound, s.DeleteCustomSignature(ctx, "zz-custom"))
	assert.ErrorIs(t, store.ErrSignatureNotFound, s.SetSignatureEnabled(ctx, "zz-custom", true))
}

func TestSignatureSourceConstraint(t *testing.T) {
	_, pool := newStore(t)

	_, err := pool.Exec(ctx, `INSERT INTO signatures (id, name, yaml, source) VALUES ('x', 'x', 'id: x', 'plugin')`)

	assert.Error(t, err)
	var src string
	must.Nil(pool.QueryRow(ctx, `INSERT INTO signatures (id, name, yaml) VALUES ('y', 'y', 'id: y') RETURNING source`).Scan(&src))
	assert.Equal(t, "builtin", src)
}
