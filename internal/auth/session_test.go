package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ctx42/testing/pkg/assert"
)

func TestIsTLS(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	assert.False(t, IsTLS(r))
	r.Header.Set("X-Forwarded-Proto", "HTTPS")
	assert.True(t, IsTLS(r))
}
