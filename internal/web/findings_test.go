package web

import (
	"net/http"
	"strings"
	"testing"

	"github.com/ctx42/testing/pkg/assert"

	"github.com/chrobson/ramparteye/internal/auth"
)

// order returns the positions of names in body, -1 when missing.
func order(body string, names ...string) []int {
	out := make([]int, len(names))
	for i, n := range names {
		out[i] = strings.Index(body, n)
	}
	return out
}

func TestFindingsSortedBySeverity(t *testing.T) {
	e, c := assetEnv(t)

	rec := e.get("/findings", c)
	body := rec.Body.String()

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contain(t, "3 detections", body)
	pos := order(body, "MySQL without auth", "WordPress", "phpMyAdmin")
	assert.True(t, pos[0] > 0 && pos[1] > 0 && pos[2] > 0, "all listed")
	assert.True(t, pos[0] < pos[1], "High before lower severities")
	assert.Contain(t, `href="/assets/10.20.60.120/3306/tcp"`, body)
	assert.Contain(t, `aria-sort="descending"`, body)
}

func TestFindingsSortedByScore(t *testing.T) {
	e, c := assetEnv(t)

	asc := e.get("/findings?sort=score&dir=asc", c).Body.String()
	desc := e.get("/findings?sort=score", c).Body.String()

	a := order(asc, "MySQL without auth", "WordPress", "phpMyAdmin")
	d := order(desc, "MySQL without auth", "WordPress", "phpMyAdmin")
	assert.True(t, (a[0] < a[2]) != (d[0] < d[2]), "direction flips the order")
	assert.Contain(t, `href="/findings?sort=score&amp;dir=desc"`, asc)
}

func TestFindingsInvalidSort(t *testing.T) {
	e, c := assetEnv(t)

	for _, q := range []string{"?sort=name", "?dir=up", "?sort=score&dir=%3Cx%3E"} {
		rec := e.get("/findings"+q, c)
		assert.Equal(t, http.StatusBadRequest, rec.Code, q)
		assert.NotContain(t, "<x>", rec.Body.String(), q)
	}
}

func TestFindingsEmpty(t *testing.T) {
	e := newEnv(t)

	rec := e.get("/findings", e.login(t, auth.RoleViewer))

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contain(t, "No findings yet", rec.Body.String())
}
