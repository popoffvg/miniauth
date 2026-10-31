package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/popoffvg/miniauth/internal/access"
	"github.com/popoffvg/miniauth/internal/access/accesstest"
	"github.com/popoffvg/miniauth/internal/groups"
	"github.com/popoffvg/miniauth/internal/loginflow"
	"github.com/popoffvg/miniauth/internal/sessions"
	"github.com/popoffvg/miniauth/internal/users"
)

func TestForwardAuthURLGrants(t *testing.T) {
	type grantRow struct {
		resource string
		group    string
		expiry   access.Expiry
	}
	tests := []struct {
		name        string
		grants      []grantRow
		host        string
		uri         string
		noForwarded bool
		accept      string
		want        int
		body        []string
		contentType string
	}{
		{
			name:   "grant to user",
			grants: []grantRow{{resource: "root"}},
			uri:    "/dash",
			want:   http.StatusOK,
		},
		{
			name:   "grant to group",
			grants: []grantRow{{resource: "root", group: "editors"}},
			uri:    "/dash",
			want:   http.StatusOK,
		},
		{
			name:   "grant to a group the user is not in",
			grants: []grantRow{{resource: "root", group: "admins"}},
			uri:    "/dash",
			want:   http.StatusForbidden,
		},
		{
			name:   "expired grant",
			grants: []grantRow{{resource: "root", expiry: access.ExpiresAt(time.Now().Add(-time.Minute))}},
			uri:    "/dash",
			want:   http.StatusForbidden,
		},
		{
			name:   "longest prefix wins over a grant on a shorter prefix",
			grants: []grantRow{{resource: "root"}},
			uri:    "/mcp/tools",
			want:   http.StatusForbidden,
		},
		{
			name:   "grant on the longest prefix",
			grants: []grantRow{{resource: "mcp"}},
			uri:    "/mcp/tools?x=1",
			want:   http.StatusOK,
		},
		{
			name:   "prefix stops at a segment border",
			grants: []grantRow{{resource: "mcp"}},
			uri:    "/mcpx",
			want:   http.StatusForbidden,
		},
		{
			name:        "no resource is a browser page",
			grants:      []grantRow{{resource: "root"}},
			host:        "other.example.test",
			uri:         "/dash?token=query-secret",
			accept:      "text/html",
			want:        http.StatusForbidden,
			body:        []string{"<strong>ada</strong>", "https://other.example.test/dash"},
			contentType: "text/html; charset=utf-8",
		},
		{
			name:        "no grant is a problem for an API client",
			uri:         "/dash?token=query-secret",
			accept:      "application/json",
			want:        http.StatusForbidden,
			body:        []string{"The user ada has no access to https://dash.example.test/dash."},
			contentType: "application/problem+json",
		},
		{
			name:        "missing forwarded headers are denied",
			grants:      []grantRow{{resource: "root"}},
			noForwarded: true,
			accept:      "application/json",
			want:        http.StatusForbidden,
			body:        []string{"The user ada has no access to the requested URL."},
			contentType: "application/problem+json",
		},
		{
			name:   "dot segments are denied",
			grants: []grantRow{{resource: "root"}},
			uri:    "/dash/../mcp",
			want:   http.StatusForbidden,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fixture := newGrantFixture(t)
			for _, row := range tt.grants {
				subject := access.UserSubject(fixture.user)
				if row.group != "" {
					name, err := groups.ParseName(row.group)
					require.NoError(t, err)
					subject = access.GroupSubject(name)
				}
				resource, err := access.ParseResourceName(row.resource)
				require.NoError(t, err)
				require.NoError(t, fixture.repo.CreateGrant(t.Context(), access.Grant{
					ID:        access.NewGrantID(),
					Resource:  resource,
					Subject:   subject,
					Expiry:    row.expiry,
					CreatedAt: time.Now(),
				}))
			}
			host := tt.host
			if host == "" {
				host = "dash.example.test"
			}
			if tt.noForwarded {
				host = ""
			}
			rec := fixture.check(t, host, tt.uri, tt.accept)

			require.Equal(t, tt.want, rec.Code, rec.Body.String())
			if tt.want == http.StatusOK {
				assert.Equal(t, "ada", rec.Header().Get(headerAuthUser))
			} else {
				assert.Empty(t, rec.Header().Get(headerAuthUser))
			}
			for _, part := range tt.body {
				assert.Contains(t, rec.Body.String(), part)
			}
			if tt.contentType != "" {
				assert.Equal(t, tt.contentType, rec.Header().Get("Content-Type"))
			}
			assert.NotContains(t, rec.Body.String(), "query-secret")
			assert.NotContains(t, rec.Body.String(), fixture.cookie)
		})
	}
}

func TestForwardAuthRevokeAppliesToTheNextRequest(t *testing.T) {
	fixture := newGrantFixture(t)
	root, err := access.ParseResourceName("root")
	require.NoError(t, err)
	id := grantResource(t, fixture.grants, root, access.UserSubject(fixture.user))

	require.Equal(t, http.StatusOK, fixture.check(t, "dash.example.test", "/dash", "").Code)
	require.NoError(t, fixture.grants.Revoke(t.Context(), id))
	require.Equal(t, http.StatusForbidden, fixture.check(t, "dash.example.test", "/dash", "").Code)
}

// grantFixture is the user ada in the group editors, with a session and two resources:
// root on dash.example.test "/" and mcp on dash.example.test "/mcp". No grant is stored.
type grantFixture struct {
	router http.Handler
	repo   *accesstest.Repository
	grants *access.Service
	user   users.ID
	cookie string
}

func newGrantFixture(t *testing.T) grantFixture {
	t.Helper()
	accounts := &memRepo{}
	ada := users.User{ID: users.NewID(), Login: mustLogin(t, "ada"), CreatedAt: time.Now().UTC()}
	accounts.put(ada)
	members := newMemGroups()
	editors, err := groups.ParseName("editors")
	require.NoError(t, err)
	require.NoError(t, members.Add(t.Context(), ada.ID, editors))
	browser := sessions.NewService(newMemSessions())
	id, _, err := browser.Start(t.Context(), ada.ID, loginflow.Factors(loginflow.FactorPassword))
	require.NoError(t, err)
	repo := accesstest.NewRepository()
	grants := access.NewService(repo, nil)
	createResource(t, grants, "root", "dash.example.test", "/")
	createResource(t, grants, "mcp", "dash.example.test", "/mcp")
	router := forwardRouter(t, accounts, browser, members, mustDomain(t, ".example.test"), mustPublicURL(t, "https://id.example.test"), WithURLGrants(grants))
	return grantFixture{router: router, repo: repo, grants: grants, user: ada.ID, cookie: id.CookieValue()}
}

// check sends no forwarded header when host is empty.
func (f grantFixture) check(t *testing.T, host, uri, accept string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/auth/check", nil)
	req.AddCookie(&http.Cookie{Name: sessions.CookieName, Value: f.cookie})
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	if host != "" {
		req.Header.Set("X-Forwarded-Proto", "https")
		req.Header.Set("X-Forwarded-Host", host)
		req.Header.Set("X-Forwarded-Uri", uri)
	}
	rec := httptest.NewRecorder()
	f.router.ServeHTTP(rec, req)
	return rec
}
