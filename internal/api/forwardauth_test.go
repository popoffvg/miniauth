package api

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
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
	returnTo := "https://app.example.test/dash?x=1"
	loginWithReturn := public.Login(returnTo)

	tests := []struct {
		name        string
		login       string
		groups      []string
		factors     loginflow.Factors
		query       string
		cookie      bool
		badCookie   bool
		accept      string
		secFetch    string
		authz       string
		forwarded   bool
		evilHost    bool
		want        int
		user        string
		email       string
		groupList   string
		method      string
		location    string
		clearCookie bool
	}{
		{
			name:      "valid session",
			login:     "ada",
			groups:    []string{"editors", "admins"},
			factors:   loginflow.Factors(loginflow.FactorPassword),
			query:     "?scope=",
			cookie:    true,
			want:      http.StatusOK,
			user:      "ada",
			groupList: "admins,editors",
			method:    "password",
		},
		{
			name:    "valid session with an email login",
			login:   "ada@example.test",
			factors: loginflow.Factors(loginflow.FactorPassword | loginflow.FactorTOTP),
			cookie:  true,
			want:    http.StatusOK,
			user:    "ada@example.test",
			email:   "ada@example.test",
			method:  "password,totp",
		},
		{
			name:    "user not in group",
			login:   "ada",
			groups:  []string{"readers"},
			factors: loginflow.Factors(loginflow.FactorPassword),
			query:   "?group=editors",
			cookie:  true,
			want:    http.StatusForbidden,
		},
		{
			name:      "user in group",
			login:     "ada",
			groups:    []string{"editors"},
			factors:   loginflow.Factors(loginflow.FactorPassword),
			query:     "?scope=openid&group=editors",
			cookie:    true,
			want:      http.StatusOK,
			user:      "ada",
			groupList: "editors",
			method:    "password",
		},
		{
			name:      "browser request without a session",
			accept:    "text/html,application/xhtml+xml",
			forwarded: true,
			want:      http.StatusFound,
			location:  loginWithReturn,
		},
		{
			name:      "browser navigation without a session",
			secFetch:  "navigate",
			forwarded: true,
			want:      http.StatusFound,
			location:  loginWithReturn,
		},
		{
			name:   "other request without a session",
			accept: "application/json",
			want:   http.StatusUnauthorized,
		},
		{
			name:      "bearer client is not sent to the login page",
			accept:    "text/html",
			authz:     "Bearer idp_test",
			forwarded: true,
			want:      http.StatusUnauthorized,
		},
		{
			name:        "bad cookie on a browser request",
			badCookie:   true,
			accept:      "text/html",
			forwarded:   true,
			want:        http.StatusFound,
			location:    loginWithReturn,
			clearCookie: true,
		},
		{
			name:      "outside return host has no return query",
			accept:    "text/html",
			forwarded: true,
			evilHost:  true,
			want:      http.StatusFound,
			location:  public.Login(""),
		},
		{
			name:    "invalid group name",
			login:   "ada",
			factors: loginflow.Factors(loginflow.FactorPassword),
			query:   "?group=../editors",
			cookie:  true,
			want:    http.StatusForbidden,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			accounts := &memRepo{}
			members := newMemGroups()
			browser := sessions.NewService(newMemSessions())
			var cookieValue string
			if tt.login != "" {
				login := mustLogin(t, tt.login)
				account := users.User{ID: users.NewID(), Login: login, CreatedAt: time.Now().UTC()}
				accounts.put(account)
				for _, raw := range tt.groups {
					name, err := groups.ParseName(raw)
					require.NoError(t, err)
					require.NoError(t, members.Add(t.Context(), account.ID, name))
				}
				if tt.cookie {
					id, _, err := browser.Start(t.Context(), account.ID, tt.factors)
					require.NoError(t, err)
					cookieValue = id.CookieValue()
				}
			}
			router := forwardRouter(t, accounts, browser, members, domain, public)
			target := "/auth/check" + tt.query
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, target, nil)
			if cookieValue != "" {
				req.AddCookie(&http.Cookie{Name: sessions.CookieName, Value: cookieValue})
			}
			if tt.badCookie {
				req.AddCookie(&http.Cookie{Name: sessions.CookieName, Value: "not-a-session"})
			}
			if tt.accept != "" {
				req.Header.Set("Accept", tt.accept)
			}
			if tt.secFetch != "" {
				req.Header.Set("Sec-Fetch-Mode", tt.secFetch)
			}
			if tt.authz != "" {
				req.Header.Set("Authorization", tt.authz)
			}
			if tt.forwarded {
				host := "app.example.test"
				if tt.evilHost {
					host = "evil.example"
				}
				req.Header.Set("X-Forwarded-Proto", "https")
				req.Header.Set("X-Forwarded-Host", host)
				req.Header.Set("X-Forwarded-Uri", "/dash?x=1")
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
			if tt.clearCookie {
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

func forwardRouter(t *testing.T, accounts *memRepo, browser *sessions.Service, members groups.Repository, domain sessions.Domain, public PublicURL) http.Handler {
	t.Helper()
	router, err := NewRouter(users.NewService(accounts), browser, members, domain, public, hashToken(t, "bootstrap-token-for-tests"), slog.New(slog.DiscardHandler))
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
	rows map[users.ID][]groups.Name
}

func newMemGroups() *memGroups {
	return &memGroups{rows: map[users.ID][]groups.Name{}}
}

func (m *memGroups) List(_ context.Context, userID users.ID) ([]groups.Name, error) {
	return append([]groups.Name(nil), m.rows[userID]...), nil
}

func (m *memGroups) Add(_ context.Context, userID users.ID, name groups.Name) error {
	for _, have := range m.rows[userID] {
		if have == name {
			return groups.ErrDuplicate
		}
	}
	m.rows[userID] = append(m.rows[userID], name)
	return nil
}

var _ groups.Repository = (*memGroups)(nil)
