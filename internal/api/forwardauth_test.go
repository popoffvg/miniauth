package api

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/popoffvg/miniauth/internal/groups"
	"github.com/popoffvg/miniauth/internal/loginflow"
	"github.com/popoffvg/miniauth/internal/sessions"
	"github.com/popoffvg/miniauth/internal/users"
)

func TestForwardAuth(t *testing.T) {
	public := mustPublicURL(t, "https://id.example.test")
	domain := mustDomain(t, ".example.test")
	const loginPage = "https://id.example.test/login"
	const loginWithReturn = "https://id.example.test/login?return=https%3A%2F%2Fapp.example.test%2Fdash%3Fx%3D1"
	const loginWithHostOnlyReturn = "https://id.example.test/login?return=https%3A%2F%2Fid.example.test%2Fdash%3Fx%3D1"

	tests := []struct {
		name             string
		login            string
		groups           []string
		factors          loginflow.Factors
		query            string
		hasCookie        bool
		hasBadCookie     bool
		accept           string
		secFetch         string
		authorization    string
		isForwarded      bool
		host             string
		uri              string
		xhr              bool
		hostOnly         bool
		missingUser      bool
		groupsFail       bool
		userFail         bool
		staleCookie      bool
		sessionStoreDown bool
		want             int
		user             string
		email            string
		groupList        string
		method           string
		location         string
		clearsCookie     bool
	}{
		{
			name:      "valid session",
			login:     "ada",
			groups:    []string{"editors", "admins"},
			factors:   loginflow.Factors(loginflow.FactorPassword),
			query:     "?scope=",
			hasCookie: true,
			want:      http.StatusOK,
			user:      "ada",
			groupList: "admins,editors",
			method:    "password",
		},
		{
			name:      "valid session with an email login",
			login:     "ada@example.test",
			factors:   loginflow.Factors(loginflow.FactorPassword | loginflow.FactorTOTP),
			hasCookie: true,
			want:      http.StatusOK,
			user:      "ada@example.test",
			email:     "ada@example.test",
			method:    "password,totp",
		},
		{
			name:      "user not in group",
			login:     "ada",
			groups:    []string{"readers"},
			factors:   loginflow.Factors(loginflow.FactorPassword),
			query:     "?group=editors",
			hasCookie: true,
			want:      http.StatusForbidden,
		},
		{
			name:      "user in group",
			login:     "ada",
			groups:    []string{"editors"},
			factors:   loginflow.Factors(loginflow.FactorPassword),
			query:     "?scope=openid&group=editors",
			hasCookie: true,
			want:      http.StatusOK,
			user:      "ada",
			groupList: "editors",
			method:    "password",
		},
		{
			name:        "browser request without a session",
			accept:      "text/html,application/xhtml+xml",
			isForwarded: true,
			host:        "app.example.test",
			uri:         "/dash?x=1",
			want:        http.StatusFound,
			location:    loginWithReturn,
		},
		{
			name:        "browser navigation without a session",
			secFetch:    "navigate",
			isForwarded: true,
			host:        "app.example.test",
			uri:         "/dash?x=1",
			want:        http.StatusFound,
			location:    loginWithReturn,
		},
		{
			name:   "other request without a session",
			accept: "application/json",
			want:   http.StatusUnauthorized,
		},
		{
			name:          "bearer client is not sent to the login page",
			accept:        "text/html",
			authorization: "Bearer idp_test",
			isForwarded:   true,
			host:          "app.example.test",
			uri:           "/dash?x=1",
			want:          http.StatusUnauthorized,
		},
		{
			name:         "bad cookie on a browser request",
			hasBadCookie: true,
			accept:       "text/html",
			isForwarded:  true,
			host:         "app.example.test",
			uri:          "/dash?x=1",
			want:         http.StatusFound,
			location:     loginWithReturn,
			clearsCookie: true,
		},
		{
			name:        "outside return host has no return query",
			accept:      "text/html",
			isForwarded: true,
			host:        "evil.example",
			uri:         "/dash?x=1",
			want:        http.StatusFound,
			location:    loginPage,
		},
		{
			name:      "invalid group name",
			login:     "ada",
			factors:   loginflow.Factors(loginflow.FactorPassword),
			query:     "?group=../editors",
			hasCookie: true,
			want:      http.StatusForbidden,
		},
		{
			name:      "empty group query",
			login:     "ada",
			factors:   loginflow.Factors(loginflow.FactorPassword),
			query:     "?group=",
			hasCookie: true,
			want:      http.StatusForbidden,
		},
		{
			name:      "blank group query",
			login:     "ada",
			factors:   loginflow.Factors(loginflow.FactorPassword),
			query:     "?group=%20",
			hasCookie: true,
			want:      http.StatusForbidden,
		},
		{
			name:      "malformed group query",
			login:     "ada",
			factors:   loginflow.Factors(loginflow.FactorPassword),
			query:     "?group=%ZZ",
			hasCookie: true,
			want:      http.StatusForbidden,
		},
		{
			name:      "user in every requested group",
			login:     "ada",
			groups:    []string{"editors", "admins"},
			factors:   loginflow.Factors(loginflow.FactorPassword),
			query:     "?group=editors&group=admins",
			hasCookie: true,
			want:      http.StatusOK,
			user:      "ada",
			groupList: "admins,editors",
			method:    "password",
		},
		{
			name:        "question mark in forwarded host has no return query",
			accept:      "text/html",
			isForwarded: true,
			host:        "evil.com?.example.test",
			uri:         "/dash?x=1",
			want:        http.StatusFound,
			location:    loginPage,
		},
		{
			name:        "hash in forwarded host has no return query",
			accept:      "text/html",
			isForwarded: true,
			host:        "evil.com#.example.test",
			uri:         "/dash?x=1",
			want:        http.StatusFound,
			location:    loginPage,
		},
		{
			name:        "unsafe forwarded uri has no return query",
			accept:      "text/html",
			isForwarded: true,
			host:        "app.example.test",
			uri:         "//evil.example",
			want:        http.StatusFound,
			location:    loginPage,
		},
		{
			name:        "xhr is not sent to the login page",
			accept:      "text/html",
			isForwarded: true,
			host:        "app.example.test",
			uri:         "/dash?x=1",
			xhr:         true,
			want:        http.StatusUnauthorized,
		},
		{
			name:        "cors fetch is not sent to the login page",
			accept:      "text/html",
			secFetch:    "cors",
			isForwarded: true,
			host:        "app.example.test",
			uri:         "/dash?x=1",
			want:        http.StatusUnauthorized,
		},
		{
			name:         "deleted user",
			factors:      loginflow.Factors(loginflow.FactorPassword),
			accept:       "text/html",
			isForwarded:  true,
			host:         "app.example.test",
			uri:          "/dash?x=1",
			missingUser:  true,
			want:         http.StatusFound,
			location:     loginWithReturn,
			clearsCookie: true,
		},
		{
			name:       "group list failure",
			login:      "ada",
			factors:    loginflow.Factors(loginflow.FactorPassword),
			hasCookie:  true,
			groupsFail: true,
			want:       http.StatusInternalServerError,
		},
		{
			name:        "user lookup failure",
			factors:     loginflow.Factors(loginflow.FactorPassword),
			hasCookie:   true,
			missingUser: true,
			userFail:    true,
			want:        http.StatusInternalServerError,
		},
		{
			name:        "host-only cookie keeps a matching return host",
			accept:      "text/html",
			isForwarded: true,
			hostOnly:    true,
			host:        "id.example.test",
			uri:         "/dash?x=1",
			want:        http.StatusFound,
			location:    loginWithHostOnlyReturn,
		},
		{
			name:        "host-only cookie drops a different return host",
			accept:      "text/html",
			isForwarded: true,
			hostOnly:    true,
			host:        "app.example.test",
			uri:         "/dash?x=1",
			want:        http.StatusFound,
			location:    loginPage,
		},
		{
			name:   "html quality zero is not a browser",
			accept: "text/html;q=0, application/json",
			want:   http.StatusUnauthorized,
		},
		{
			name:        "html quality above zero is a browser",
			accept:      "text/html;q=0.5, application/json",
			isForwarded: true,
			host:        "app.example.test",
			uri:         "/dash?x=1",
			want:        http.StatusFound,
			location:    loginWithReturn,
		},
		{
			name:        "bracketed dns host has no return query",
			accept:      "text/html",
			isForwarded: true,
			host:        "[app.example.test]:443",
			uri:         "/dash?x=1",
			want:        http.StatusFound,
			location:    loginPage,
		},
		{
			name:        "stale cookie before a valid cookie",
			login:       "ada",
			factors:     loginflow.Factors(loginflow.FactorPassword),
			hasCookie:   true,
			staleCookie: true,
			want:        http.StatusOK,
			user:        "ada",
			method:      "password",
		},
		{
			name:             "session store failure",
			sessionStoreDown: true,
			want:             http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stored := &memRepo{}
			var accounts users.Repository = stored
			if tt.userFail {
				accounts = failRepo{}
			}
			members := newMemGroups()
			var groupList groups.Repository = members
			if tt.groupsFail {
				groupList = failGroups{}
			}
			browser := sessions.NewService(newMemSessions())
			var cookieValue string
			if tt.missingUser {
				id, _, err := browser.Start(t.Context(), users.NewID(), tt.factors)
				require.NoError(t, err)
				cookieValue = id.CookieValue()
			}
			if tt.login != "" {
				login := mustLogin(t, tt.login)
				user := users.User{ID: users.NewID(), Login: login, CreatedAt: time.Now().UTC()}
				stored.put(user)
				for _, raw := range tt.groups {
					name, err := groups.ParseName(raw)
					require.NoError(t, err)
					require.NoError(t, members.Add(t.Context(), user.ID, name))
				}
				if tt.hasCookie {
					id, _, err := browser.Start(t.Context(), user.ID, tt.factors)
					require.NoError(t, err)
					cookieValue = id.CookieValue()
				}
			}
			checkDomain := domain
			if tt.hostOnly {
				checkDomain = sessions.Domain{}
			}
			if tt.sessionStoreDown {
				id, err := sessions.NewID()
				require.NoError(t, err)
				cookieValue = id.CookieValue()
				browser = sessions.NewService(failSessions{})
			}
			router := forwardRouter(t, accounts, browser, groupList, checkDomain, public)
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/auth/check", nil)
			req.URL.RawQuery = strings.TrimPrefix(tt.query, "?")
			if tt.staleCookie {
				stale, err := sessions.NewID()
				require.NoError(t, err)
				req.AddCookie(&http.Cookie{Name: sessions.CookieName, Value: stale.CookieValue()})
			}
			if cookieValue != "" {
				req.AddCookie(&http.Cookie{Name: sessions.CookieName, Value: cookieValue})
			}
			if tt.hasBadCookie {
				req.AddCookie(&http.Cookie{Name: sessions.CookieName, Value: "not-a-session"})
			}
			if tt.accept != "" {
				req.Header.Set("Accept", tt.accept)
			}
			if tt.secFetch != "" {
				req.Header.Set("Sec-Fetch-Mode", tt.secFetch)
			}
			if tt.authorization != "" {
				req.Header.Set("Authorization", tt.authorization)
			}
			if tt.xhr {
				req.Header.Set("X-Requested-With", "XMLHttpRequest")
			}
			if tt.isForwarded {
				req.Header.Set("X-Forwarded-Proto", "https")
				req.Header.Set("X-Forwarded-Host", tt.host)
				req.Header.Set("X-Forwarded-Uri", tt.uri)
			}
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)

			require.Equal(t, tt.want, rec.Code)
			assert.Equal(t, tt.user, rec.Header().Get(headerAuthUser))
			assert.Equal(t, tt.email, rec.Header().Get(headerAuthEmail))
			assert.Equal(t, tt.groupList, rec.Header().Get(headerAuthGroups))
			assert.Equal(t, tt.method, rec.Header().Get(headerAuthMethod))
			assert.Equal(t, tt.location, rec.Header().Get("Location"))
			if tt.want == http.StatusUnauthorized {
				assert.Equal(t, "Bearer", rec.Header().Get("WWW-Authenticate"))
			} else {
				assert.Empty(t, rec.Header().Get("WWW-Authenticate"))
			}
			if tt.want == http.StatusInternalServerError {
				assert.Contains(t, rec.Body.String(), "The check failed.")
				assert.NotContains(t, rec.Body.String(), "groups are down")
				assert.NotContains(t, rec.Body.String(), "database is down")
				assert.NotContains(t, rec.Body.String(), "sessions are down")
			}
			if tt.clearsCookie {
				cleared := mustParseSetCookie(t, rec)
				assert.Equal(t, sessions.CookieName, cleared.Name)
				assert.Negative(t, cleared.MaxAge)
				assert.NotContains(t, rec.Header().Get("Set-Cookie"), "not-a-session")
			}
			if cookieValue != "" {
				assert.NotContains(t, rec.Body.String(), cookieValue)
				assert.NotContains(t, rec.Header().Get("Location"), cookieValue)
			}
			assert.NotContains(t, rec.Body.String(), "idp_test")
			if tt.location != "" {
				parsed, err := url.Parse(rec.Header().Get("Location"))
				require.NoError(t, err)
				assert.Equal(t, "/login", parsed.Path)
			}
		})
	}
}

func TestForwardedHostname(t *testing.T) {
	tests := []struct {
		host string
		want string
		ok   bool
	}{
		{host: "app.example.test", want: "app.example.test", ok: true},
		{host: "app.example.test:443", want: "app.example.test", ok: true},
		{host: "[2001:db8::1]:443", want: "2001:db8::1", ok: true},
		{host: "[::1]", want: "::1", ok: true},
		{host: "[app.example.test]:443", ok: false},
		{host: "[127.0.0.1]:443", ok: false},
		{host: "app.example.test:99999", ok: false},
	}
	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			got, ok := forwardedHostname(tt.host)
			assert.Equal(t, tt.ok, ok)
			assert.Equal(t, tt.want, got)
		})
	}
}

func forwardRouter(t *testing.T, accounts users.Repository, browser *sessions.Service, members groups.Repository, domain sessions.Domain, public PublicURL) http.Handler {
	t.Helper()
	router, err := NewRouter(users.NewService(accounts), browser, members, domain, public, hashToken(t, "bootstrap-token-for-tests"), &readyState{ok: true}, slog.New(slog.DiscardHandler))
	require.NoError(t, err)
	return router
}

func mustPublicURL(t *testing.T, raw string) PublicURL {
	t.Helper()
	parsed, err := ParsePublicURL(raw)
	require.NoError(t, err)
	return parsed
}

type memGroups struct {
	byUser map[users.ID][]groups.Name
}

func newMemGroups() *memGroups {
	return &memGroups{byUser: map[users.ID][]groups.Name{}}
}

func (m *memGroups) List(_ context.Context, userID users.ID) ([]groups.Name, error) {
	return slices.Clone(m.byUser[userID]), nil
}

func (m *memGroups) Add(_ context.Context, userID users.ID, name groups.Name) error {
	if slices.Contains(m.byUser[userID], name) {
		return groups.ErrDuplicate
	}
	m.byUser[userID] = append(m.byUser[userID], name)
	return nil
}

type failGroups struct{}

func (failGroups) List(context.Context, users.ID) ([]groups.Name, error) {
	return nil, errors.New("groups are down")
}

type failSessions struct{}

func (failSessions) Create(context.Context, sessions.Session, sessions.Hash) error {
	return errors.New("sessions are down")
}

func (failSessions) Find(context.Context, sessions.Hash) (sessions.Session, sessions.Hash, error) {
	return sessions.Session{}, sessions.Hash{}, errors.New("sessions are down")
}

func (failSessions) Extend(context.Context, sessions.Hash, time.Time, time.Time) (bool, error) {
	return false, errors.New("sessions are down")
}

func (failSessions) Delete(context.Context, sessions.Hash) error {
	return errors.New("sessions are down")
}

func (failSessions) DeleteUser(context.Context, users.ID) error {
	return errors.New("sessions are down")
}

var _ groups.Repository = (*memGroups)(nil)
