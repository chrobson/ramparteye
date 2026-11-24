package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ctx42/testing/pkg/assert"

	"github.com/chrobson/ramparteye/internal/store"
)

func init() { bcryptCost = 4 }

var t0 = time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)

type fakeStore struct {
	users    map[string]store.User
	sessions map[string]sess

	expiredCalls int
}

type sess struct {
	userID  int64
	expires time.Time
}

func newFake(users ...store.User) *fakeStore {
	f := &fakeStore{users: map[string]store.User{}, sessions: map[string]sess{}}
	for _, u := range users {
		f.users[u.Login] = u
	}
	return f
}

func (f *fakeStore) UserByLogin(_ context.Context, login string) (store.User, error) {
	u, ok := f.users[login]
	if !ok {
		return store.User{}, store.ErrUserNotFound
	}
	return u, nil
}

func (f *fakeStore) CreateSession(_ context.Context, h []byte, uid int64, exp time.Time) error {
	f.sessions[string(h)] = sess{uid, exp}
	return nil
}

func (f *fakeStore) SessionUserAt(_ context.Context, h []byte, now time.Time) (store.User, error) {
	s, ok := f.sessions[string(h)]
	if !ok || !s.expires.After(now) {
		return store.User{}, store.ErrUserNotFound
	}
	for _, u := range f.users {
		if u.ID == s.userID {
			return u, nil
		}
	}
	return store.User{}, store.ErrUserNotFound
}

func (f *fakeStore) DeleteExpiredSessions(context.Context) (int64, error) {
	f.expiredCalls++
	return 0, nil
}

func (f *fakeStore) DeleteSession(_ context.Context, h []byte) error {
	delete(f.sessions, string(h))
	return nil
}

func permStrings(role string) []string {
	var out []string
	for _, p := range BuiltinRoles[role] {
		out = append(out, string(p))
	}
	return out
}

func mkUser(id int64, login, role, pw string, must bool) store.User {
	h, err := HashPassword(pw)
	if err != nil {
		panic(err)
	}
	return store.User{ID: id, Login: login, PasswordHash: h, RoleName: role,
		Perms: permStrings(role), MustChangePassword: must}
}

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
}

func TestBuiltinRolesMatrix(t *testing.T) {
	want := map[string]map[Perm]bool{
		RoleAdmin:    {},
		RoleOperator: {},
		RoleAnalyst:  {PermTargetsRead: true, PermResultsRead: true, PermResultsEdit: true, PermExport: true},
		RoleViewer:   {PermTargetsRead: true, PermResultsRead: true},
	}
	for _, p := range AllPerms {
		want[RoleAdmin][p] = true
		want[RoleOperator][p] = p != PermUsersAdmin && p != PermSettingsAdmin
	}
	assert.Len(t, 4, BuiltinRoles)
	for role, perms := range want {
		for _, p := range AllPerms {
			u := User{Perms: BuiltinRoles[role]}
			assert.Equal(t, perms[p], u.Can(p), "%s %s", role, p)
		}
	}
}

func TestCanWithoutUser(t *testing.T) {
	assert.False(t, Can(context.Background(), PermTargetsRead))
	ctx := WithUser(context.Background(), User{Perms: []Perm{PermExport}})
	assert.True(t, Can(ctx, PermExport))
	assert.False(t, Can(ctx, PermScansRun))
}

func TestPasswordLimits(t *testing.T) {
	_, err := HashPassword("short")
	assert.ErrorIs(t, ErrWeakPassword, err)
	_, err = HashPassword(strings.Repeat("a", 73))
	assert.ErrorIs(t, ErrLongPassword, err)
	h, err := HashPassword(strings.Repeat("a", 72))
	assert.NoError(t, err)
	assert.True(t, CheckPassword(h, strings.Repeat("a", 72)))
	assert.False(t, CheckPassword(h, "wrong-password"))
}

// handlerChain builds Middleware -> mux with a protected POST route.
func handlerChain(f *fakeStore, now func() time.Time) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("POST /annotations", Require(PermResultsEdit)(okHandler()))
	mux.Handle("/", okHandler())
	return Middleware(f, now)(mux)
}

func loginAs(t *testing.T, f *fakeStore, login, pw string) string {
	t.Helper()
	a := NewAuthenticator(f, f, func() time.Time { return t0 })
	tok, _, err := a.Login(context.Background(), login, pw, "10.0.0.1")
	assert.NoError(t, err)
	return tok
}

func reqWithCookie(method, path, tok string) *http.Request {
	r := httptest.NewRequest(method, path, nil)
	r.AddCookie(&http.Cookie{Name: CookieName, Value: tok})
	return r
}

func TestViewerCannotEdit(t *testing.T) {
	f := newFake(mkUser(1, "vic", RoleViewer, "password-1", false),
		mkUser(2, "ann", RoleAnalyst, "password-2", false))
	h := handlerChain(f, func() time.Time { return t0 })

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, reqWithCookie("POST", "/annotations", loginAs(t, f, "vic", "password-1")))
	assert.Equal(t, http.StatusForbidden, rec.Code)

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, reqWithCookie("POST", "/annotations", loginAs(t, f, "ann", "password-2")))
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestRequireWithoutSession(t *testing.T) {
	h := handlerChain(newFake(), func() time.Time { return t0 })

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", "/annotations", nil))
	assert.Equal(t, http.StatusSeeOther, rec.Code)
	assert.Equal(t, "/login?next=%2F", rec.Header().Get("Location"))

	r := httptest.NewRequest("POST", "/annotations", nil)
	r.Header.Set("HX-Request", "true")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Equal(t, "/login", rec.Header().Get("HX-Redirect"))
}

func TestLockoutAfterFive(t *testing.T) {
	f := newFake(mkUser(1, "ann", RoleAnalyst, "right-password", false))
	now := t0
	a := NewAuthenticator(f, f, func() time.Time { return now })
	ctx := context.Background()

	for range MaxLoginFailures {
		_, _, err := a.Login(ctx, "ann", "wrong-password", "10.0.0.1")
		assert.ErrorIs(t, ErrBadCredentials, err)
	}
	// Even the right password is refused while locked, from any address.
	_, _, err := a.Login(ctx, "ann", "right-password", "10.0.0.9")
	assert.ErrorIs(t, ErrLocked, err)
	assert.Len(t, 0, f.sessions)

	now = now.Add(LoginFailureWindow)
	_, _, err = a.Login(ctx, "ann", "right-password", "10.0.0.9")
	assert.NoError(t, err)
}

func TestLoginUnknownUserCountsAsFailure(t *testing.T) {
	a := NewAuthenticator(newFake(), newFake(), func() time.Time { return t0 })
	for range MaxLoginFailures {
		_, _, err := a.Login(context.Background(), "ghost", "whatever-pw", "10.0.0.1")
		assert.ErrorIs(t, ErrBadCredentials, err)
	}
	_, _, err := a.Login(context.Background(), "ghost", "whatever-pw", "10.0.0.1")
	assert.ErrorIs(t, ErrLocked, err)
}

func TestSessionStoresOnlyTokenHash(t *testing.T) {
	f := newFake(mkUser(1, "ann", RoleAnalyst, "password-2", false))
	tok := loginAs(t, f, "ann", "password-2")
	assert.Len(t, 43, tok) // 32 bytes, base64url without padding
	assert.Len(t, 1, f.sessions)
	for k := range f.sessions {
		assert.Equal(t, string(HashToken(tok)), k)
		assert.NotEqual(t, tok, k)
	}
}

func TestSessionExpiresAfter12h(t *testing.T) {
	f := newFake(mkUser(1, "ann", RoleAnalyst, "password-2", false))
	now := t0
	a := NewAuthenticator(f, f, func() time.Time { return now })
	tok, exp, err := a.Login(context.Background(), "ann", "password-2", "10.0.0.1")
	assert.NoError(t, err)
	assert.Equal(t, t0.Add(12*time.Hour), exp)

	h := handlerChain(f, func() time.Time { return now })
	call := func() int {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, reqWithCookie("POST", "/annotations", tok))
		return rec.Code
	}
	now = t0.Add(12*time.Hour - time.Second)
	assert.Equal(t, http.StatusOK, call())
	now = t0.Add(12 * time.Hour)
	assert.Equal(t, http.StatusSeeOther, call()) // session gone: redirected to login
}

func TestLogoutDeletesSession(t *testing.T) {
	f := newFake(mkUser(1, "ann", RoleAnalyst, "password-2", false))
	tok := loginAs(t, f, "ann", "password-2")
	a := NewAuthenticator(f, f, func() time.Time { return t0 })
	assert.NoError(t, a.Logout(context.Background(), reqWithCookie("POST", "/logout", tok)))
	assert.Len(t, 0, f.sessions)
}

func TestMustChangePasswordRedirects(t *testing.T) {
	f := newFake(mkUser(1, "adm", RoleAdmin, "password-1", true))
	h := handlerChain(f, func() time.Time { return t0 })
	tok := loginAs(t, f, "adm", "password-1")

	for _, p := range []string{"/", "/targets", "/annotations", "/staticx/app.css"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, reqWithCookie("GET", p, tok))
		assert.Equal(t, http.StatusSeeOther, rec.Code, p)
		assert.Equal(t, "/account/password", rec.Header().Get("Location"), p)
	}
	for _, p := range []string{"/account/password", "/logout", "/static/app.css"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, reqWithCookie("GET", p, tok))
		assert.Equal(t, http.StatusOK, rec.Code, p)
	}
}

func TestSessionCookieAttributes(t *testing.T) {
	rec := httptest.NewRecorder()
	SetSessionCookie(rec, httptest.NewRequest("GET", "/", nil), "tok", t0.Add(SessionTTL), t0)
	c := rec.Result().Cookies()[0]
	assert.Equal(t, "rampart_session", c.Name)
	assert.True(t, c.HttpOnly)
	assert.False(t, c.Secure)
	assert.Equal(t, http.SameSiteLaxMode, c.SameSite)
	assert.Equal(t, 12*3600, c.MaxAge)

	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("X-Forwarded-Proto", "https")
	rec = httptest.NewRecorder()
	SetSessionCookie(rec, r, "tok", t0.Add(SessionTTL), t0)
	assert.True(t, rec.Result().Cookies()[0].Secure)

	rec = httptest.NewRecorder()
	ClearSessionCookie(rec, r)
	assert.Equal(t, -1, rec.Result().Cookies()[0].MaxAge)
}

func TestCSRFRejectsMissingToken(t *testing.T) {
	h := CSRF(okHandler())
	post := func(hdr map[string]string) int {
		r := httptest.NewRequest("POST", "http://rampart.local/targets", nil)
		for k, v := range hdr {
			r.Header.Set(k, v)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		return rec.Code
	}
	assert.Equal(t, http.StatusForbidden, post(map[string]string{"Sec-Fetch-Site": "cross-site"}))
	assert.Equal(t, http.StatusForbidden, post(map[string]string{"Origin": "https://evil.example"}))
	assert.Equal(t, http.StatusOK, post(map[string]string{"Sec-Fetch-Site": "same-origin"}))
	assert.Equal(t, http.StatusOK, post(nil)) // non-browser client

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestConcurrentLoginsRespectLockout(t *testing.T) {
	f := newFake(mkUser(1, "ann", RoleAnalyst, "right-password", false))
	a := NewAuthenticator(f, f, func() time.Time { return t0 })
	var checks atomic.Int32
	a.check = func(hash, pw string) bool {
		checks.Add(1)
		time.Sleep(5 * time.Millisecond) // widen the race window
		return CheckPassword(hash, pw)
	}
	var wg sync.WaitGroup
	var locked atomic.Int32
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, err := a.Login(context.Background(), "ann", "wrong-password", "10.0.0.1")
			if errors.Is(err, ErrLocked) {
				locked.Add(1)
			}
		}()
	}
	wg.Wait()
	assert.Equal(t, int32(MaxLoginFailures), checks.Load())
	assert.Equal(t, int32(20-MaxLoginFailures), locked.Load())
}

func TestLockedErrorCarriesWait(t *testing.T) {
	f := newFake(mkUser(1, "ann", RoleAnalyst, "right-password", false))
	now := t0
	a := NewAuthenticator(f, f, func() time.Time { return now })
	for range MaxLoginFailures {
		_, _, _ = a.Login(context.Background(), "ann", "wrong-password", "10.0.0.1")
	}
	now = t0.Add(5 * time.Minute)
	_, _, err := a.Login(context.Background(), "ann", "right-password", "10.0.0.1")
	assert.ErrorIs(t, ErrLocked, err)
	var le *LockedError
	assert.True(t, errors.As(err, &le))
	assert.Equal(t, LoginFailureWindow-5*time.Minute, le.Wait)
}

func TestSuccessfulLoginsDoNotFillClientKey(t *testing.T) {
	f := newFake(mkUser(1, "ann", RoleAnalyst, "right-password", false))
	a := NewAuthenticator(f, f, func() time.Time { return t0 })
	for range 3 * MaxLoginFailures {
		_, _, err := a.Login(context.Background(), "ann", "right-password", "10.0.0.1")
		assert.NoError(t, err)
	}
}

func TestLoginPurgesExpiredSessions(t *testing.T) {
	f := newFake(mkUser(1, "ann", RoleAnalyst, "right-password", false))
	loginAs(t, f, "ann", "right-password")
	assert.Equal(t, 1, f.expiredCalls)
}

func TestOverlongLoginRejectedWithoutKeying(t *testing.T) {
	f := newFake()
	a := NewAuthenticator(f, f, func() time.Time { return t0 })
	_, _, err := a.Login(context.Background(), strings.Repeat("a", MaxLoginLen+1), "whatever-pw", "10.0.0.1")
	assert.ErrorIs(t, ErrBadCredentials, err)
	assert.Len(t, 0, a.throttle.failures)
}

func TestIPv6ClientsKeyedPerSlash64(t *testing.T) {
	assert.Equal(t, clientKey("2001:db8:1:2::1"), clientKey("2001:db8:1:2:ffff::9"))
	assert.NotEqual(t, clientKey("2001:db8:1:2::1"), clientKey("2001:db8:1:3::1"))
	assert.Equal(t, "10.0.0.1", clientKey("::ffff:10.0.0.1"))

	f := newFake()
	a := NewAuthenticator(f, f, func() time.Time { return t0 })
	for i := range MaxLoginFailures {
		ip := fmt.Sprintf("2001:db8:1:2::%x", i+1)
		_, _, err := a.Login(context.Background(), fmt.Sprintf("u%d", i), "whatever-pw", ip)
		assert.ErrorIs(t, ErrBadCredentials, err)
	}
	_, _, err := a.Login(context.Background(), "fresh", "whatever-pw", "2001:db8:1:2::ffff")
	assert.ErrorIs(t, ErrLocked, err)
}

func TestThrottleKeyCapIsHard(t *testing.T) {
	now := t0
	th := newThrottle(func() time.Time { return now })
	for i := range maxThrottleKeys + 500 {
		now = now.Add(time.Millisecond)
		_, ok, _ := th.reserve(fmt.Sprintf("k%d", i))
		assert.True(t, ok)
		assert.True(t, len(th.failures) <= maxThrottleKeys)
	}
	assert.Equal(t, maxThrottleKeys, len(th.failures))
	_, oldest := th.failures["k0"]
	assert.False(t, oldest)
	_, newest := th.failures[fmt.Sprintf("k%d", maxThrottleKeys+499)]
	assert.True(t, newest)
}

func TestCheckPasswordRejectsOverlong(t *testing.T) {
	long := strings.Repeat("a", 73)
	h, _ := HashPassword(strings.Repeat("a", 72))
	assert.False(t, CheckPassword(h, long)) // bcrypt would truncate and match
}

func TestMustChangePasswordAPIRequest(t *testing.T) {
	f := newFake(mkUser(1, "adm", RoleAdmin, "password-1", true))
	h := handlerChain(f, func() time.Time { return t0 })
	tok := loginAs(t, f, "adm", "password-1")
	r := reqWithCookie("POST", "/api/targets", tok)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Equal(t, "/account/password", rec.Header().Get("HX-Redirect"))

	r = reqWithCookie("GET", "/targets", tok)
	r.Header.Set("HX-Request", "true")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

func TestPasswordErrorsSayBytes(t *testing.T) {
	assert.Contain(t, "bytes", ErrWeakPassword.Error())
	assert.Contain(t, "bytes", ErrLongPassword.Error())
}

func TestCSRFMoreCases(t *testing.T) {
	h := CSRF(okHandler())
	do := func(method string, hdr map[string]string) int {
		r := httptest.NewRequest(method, "http://rampart.local/x", nil)
		for k, v := range hdr {
			r.Header.Set(k, v)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		return rec.Code
	}
	assert.Equal(t, http.StatusForbidden, do("POST", map[string]string{"Origin": "null"}))
	assert.Equal(t, http.StatusForbidden, do("POST", map[string]string{"Sec-Fetch-Site": "same-site"}))
	assert.Equal(t, http.StatusForbidden, do("PUT", map[string]string{"Sec-Fetch-Site": "cross-site"}))
	assert.Equal(t, http.StatusForbidden, do("DELETE", map[string]string{"Sec-Fetch-Site": "cross-site"}))
	// No Sec-Fetch-Site: Origin host is compared with Host.
	assert.Equal(t, http.StatusOK, do("POST", map[string]string{"Origin": "http://rampart.local"}))
	assert.Equal(t, http.StatusForbidden, do("POST", map[string]string{"Origin": "http://other.local"}))
}

func TestRealClockSuccessfulLoginsAreReleased(t *testing.T) {
	f := newFake(mkUser(1, "ann", RoleAnalyst, "right-password", false))
	var n int64
	clock := func() time.Time { n++; return t0.Add(time.Duration(n) * time.Microsecond) }
	a := NewAuthenticator(f, f, clock)
	for range 10 {
		_, _, err := a.Login(context.Background(), "ann", "right-password", "10.0.0.1")
		assert.NoError(t, err)
	}
	b := NewAuthenticator(f, f, time.Now)
	for range 10 {
		_, _, err := b.Login(context.Background(), "ann", "right-password", "10.0.0.2")
		assert.NoError(t, err)
	}
}

type errUsers struct{ err error }

func (e errUsers) UserByLogin(context.Context, string) (store.User, error) {
	return store.User{}, e.err
}

func TestStoreErrorKeepsEarlierFailures(t *testing.T) {
	f := newFake(mkUser(1, "ann", RoleAnalyst, "right-password", false))
	a := NewAuthenticator(f, f, func() time.Time { return t0 })
	for range MaxLoginFailures - 1 {
		_, _, err := a.Login(context.Background(), "ann", "wrong-password", "10.0.0.1")
		assert.ErrorIs(t, ErrBadCredentials, err)
	}
	a.Users = errUsers{errors.New("db down")}
	_, _, err := a.Login(context.Background(), "ann", "wrong-password", "10.0.0.1")
	assert.Error(t, err)
	assert.False(t, errors.Is(err, ErrLocked))

	a.Users = f
	_, _, err = a.Login(context.Background(), "ann", "wrong-password", "10.0.0.1")
	assert.ErrorIs(t, ErrBadCredentials, err) // 5th failure counted
	_, _, err = a.Login(context.Background(), "ann", "right-password", "10.0.0.1")
	assert.ErrorIs(t, ErrLocked, err)
}

func TestFloodCannotEvictLock(t *testing.T) {
	f := newFake(mkUser(1, "admin", RoleAdmin, "right-password", false))
	a := NewAuthenticator(f, f, func() time.Time { return t0 })
	a.throttle.maxKeys = 300 // same logic as the 10,000 default, faster to flood
	ctx := context.Background()
	for range MaxLoginFailures {
		_, _, _ = a.Login(ctx, "admin", "wrong-password", "10.0.0.1")
	}
	for i := range 1000 {
		ip := fmt.Sprintf("2001:db8:%x:%x::1", i>>16, i&0xffff)
		_, _, _ = a.Login(ctx, fmt.Sprintf("junk%d", i), "whatever-pw", ip)
	}
	_, _, err := a.Login(ctx, "admin", "right-password", "10.0.0.7")
	assert.ErrorIs(t, ErrLocked, err)
	_, _, err = a.Login(ctx, "admin", "wrong-password", "10.0.0.8")
	assert.ErrorIs(t, ErrLocked, err)
	assert.True(t, len(a.throttle.failures) <= 300)
}

func TestRequireWithCustomForbidden(t *testing.T) {
	f := newFake(mkUser(1, "vic", RoleViewer, "password-1", false))
	forbidden := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	})
	h := Middleware(f, func() time.Time { return t0 })(RequireWith(PermResultsEdit, forbidden)(okHandler()))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, reqWithCookie("GET", "/x", loginAs(t, f, "vic", "password-1")))
	assert.Equal(t, http.StatusTeapot, rec.Code)

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/x?a=1", nil))
	assert.Equal(t, http.StatusSeeOther, rec.Code)
	assert.Equal(t, "/login?next=%2Fx%3Fa%3D1", rec.Header().Get("Location"))
}

func TestVerifyIsThrottledAndCreatesNoSession(t *testing.T) {
	f := newFake(mkUser(1, "ann", RoleAnalyst, "right-password", false))
	a := NewAuthenticator(f, f, func() time.Time { return t0 })
	ctx := context.Background()

	assert.NoError(t, a.Verify(ctx, "ann", "right-password", "10.0.0.1"))
	for range MaxLoginFailures {
		assert.ErrorIs(t, ErrBadCredentials, a.Verify(ctx, "ann", "wrong-password", "10.0.0.1"))
	}
	assert.ErrorIs(t, ErrLocked, a.Verify(ctx, "ann", "right-password", "10.0.0.1"))
	assert.Len(t, 0, f.sessions)
}

func TestNewSession(t *testing.T) {
	f := newFake(mkUser(1, "ann", RoleAnalyst, "right-password", false))
	a := NewAuthenticator(f, f, func() time.Time { return t0 })

	tok, exp, err := a.NewSession(context.Background(), 1)

	assert.NoError(t, err)
	assert.Equal(t, t0.Add(SessionTTL), exp)
	assert.Equal(t, int64(1), f.sessions[string(HashToken(tok))].userID)
}

func TestDisabledUserCannotLogIn(t *testing.T) {
	u := mkUser(1, "ann", RoleAnalyst, "password-2", false)
	u.Disabled = true
	f := newFake(u)
	a := NewAuthenticator(f, f, func() time.Time { return t0 })

	_, _, err := a.Login(context.Background(), "ann", "password-2", "10.0.0.1")

	assert.ErrorIs(t, ErrBadCredentials, err)
	assert.Len(t, 0, f.sessions)
}
