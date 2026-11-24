package auth

import "net/http"

// CSRF rejects cross-origin unsafe requests using http.CrossOriginProtection
// (Sec-Fetch-Site and Origin compared with Host). Together with SameSite=Lax
// session cookies this replaces per-form tokens. Requests carrying neither
// header (non-browser clients) pass; they hold no ambient cookie authority.
func CSRF(next http.Handler) http.Handler {
	cop := http.NewCrossOriginProtection()
	cop.SetDenyHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "cross-origin request rejected (CSRF protection)", http.StatusForbidden)
	}))
	return cop.Handler(next)
}
