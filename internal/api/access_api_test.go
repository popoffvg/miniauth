package api

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/popoffvg/miniauth/internal/access"
	"github.com/popoffvg/miniauth/internal/access/accesstest"
	"github.com/popoffvg/miniauth/internal/sessions"
	"github.com/popoffvg/miniauth/internal/users"
)

const accessAdminToken = "bootstrap-token-for-tests"

func TestCreateResource(t *testing.T) {
	fixture := newAccessFixture(t)
	created := fixture.send(t, http.MethodPost, "/api/v1/resources", `{"name":"Dashboards","url":"https://Dash.Example.Test/"}`)
	require.Equal(t, http.StatusCreated, created.Code, created.Body.String())
	assert.JSONEq(t, `{"name":"dashboards","url":"dash.example.test/"}`, created.Body.String())

	tests := []struct {
		name        string
		token       string
		body        string
		contentType string
		want        int
	}{
		{name: "no token", body: `{"name":"x","url":"https://x.example.test/"}`, want: http.StatusUnauthorized},
		{name: "text body", token: accessAdminToken, body: `{"name":"x","url":"https://x.example.test/"}`, contentType: "text/plain", want: http.StatusUnsupportedMediaType},
		{name: "bad json", token: accessAdminToken, body: `{"name":`, want: http.StatusBadRequest},
		{name: "unknown field", token: accessAdminToken, body: `{"name":"x","url":"https://x.example.test/","scheme":"https"}`, want: http.StatusBadRequest},
		{name: "bad name", token: accessAdminToken, body: `{"name":"-x","url":"https://x.example.test/"}`, want: http.StatusBadRequest},
		{name: "no name", token: accessAdminToken, body: `{"url":"https://x.example.test/"}`, want: http.StatusBadRequest},
		{name: "no url", token: accessAdminToken, body: `{"name":"x"}`, want: http.StatusBadRequest},
		{name: "ftp url", token: accessAdminToken, body: `{"name":"x","url":"ftp://x.example.test/"}`, want: http.StatusBadRequest},
		{name: "url with a query", token: accessAdminToken, body: `{"name":"x","url":"https://x.example.test/?a=1"}`, want: http.StatusBadRequest},
		{name: "url with dot segments", token: accessAdminToken, body: `{"name":"x","url":"https://x.example.test/a/../b"}`, want: http.StatusBadRequest},
		{name: "duplicate name", token: accessAdminToken, body: `{"name":"dashboards","url":"https://other.example.test/"}`, want: http.StatusConflict},
		{name: "same host and prefix over http", token: accessAdminToken, body: `{"name":"copy","url":"http://dash.example.test"}`, want: http.StatusConflict},
		{name: "large body", token: accessAdminToken, body: strings.Repeat("a", maxAccessBody+1), want: http.StatusRequestEntityTooLarge},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			contentType := tt.contentType
			if contentType == "" {
				contentType = "application/json"
			}
			rec := fixture.sendAs(t, tt.token, contentType, http.MethodPost, "/api/v1/resources", tt.body)
			require.Equal(t, tt.want, rec.Code, rec.Body.String())
			assert.Contains(t, rec.Header().Get("Content-Type"), "application/problem+json")
		})
	}
	listed := fixture.send(t, http.MethodGet, "/api/v1/resources", "")
	require.Equal(t, http.StatusOK, listed.Code)
	assert.JSONEq(t, `{"resources":[{"name":"dashboards","url":"dash.example.test/"}]}`, listed.Body.String())
}

func TestListResources(t *testing.T) {
	fixture := newAccessFixture(t)
	empty := fixture.send(t, http.MethodGet, "/api/v1/resources", "")
	require.Equal(t, http.StatusOK, empty.Code)
	assert.JSONEq(t, `{"resources":[]}`, empty.Body.String())

	fixture.createResource(t, "mcp", "https://dash.example.test/mcp")
	fixture.createResource(t, "dashboards", "https://dash.example.test/")
	listed := fixture.send(t, http.MethodGet, "/api/v1/resources", "")
	require.Equal(t, http.StatusOK, listed.Code)
	assert.JSONEq(t, `{"resources":[{"name":"dashboards","url":"dash.example.test/"},{"name":"mcp","url":"dash.example.test/mcp"}]}`, listed.Body.String())

	noToken := fixture.sendAs(t, "", "", http.MethodGet, "/api/v1/resources", "")
	require.Equal(t, http.StatusUnauthorized, noToken.Code)
}

func TestDeleteResource(t *testing.T) {
	fixture := newAccessFixture(t)
	fixture.createResource(t, "dashboards", "https://dash.example.test/")
	grant := fixture.grant(t, `{"user":"ada","resource":"dashboards"}`)

	require.Equal(t, http.StatusUnauthorized, fixture.sendAs(t, "", "", http.MethodDelete, "/api/v1/resources/dashboards", "").Code)
	deleted := fixture.send(t, http.MethodDelete, "/api/v1/resources/dashboards", "")
	require.Equal(t, http.StatusNoContent, deleted.Code)
	assert.Empty(t, deleted.Body.String())

	again := fixture.send(t, http.MethodDelete, "/api/v1/resources/dashboards", "")
	require.Equal(t, http.StatusNotFound, again.Code)
	assert.Contains(t, again.Header().Get("Content-Type"), "application/problem+json")
	require.Equal(t, http.StatusNotFound, fixture.send(t, http.MethodDelete, "/api/v1/resources/-bad-", "").Code)
	require.Equal(t, http.StatusNotFound, fixture.send(t, http.MethodDelete, "/api/v1/grants/"+grant.ID, "").Code, "the grants MUST go with the resource")
}

func TestCreateGrant(t *testing.T) {
	fixture := newAccessFixture(t)
	fixture.createResource(t, "dashboards", "https://dash.example.test/")
	later := time.Now().Add(time.Hour).UTC().Truncate(time.Second)

	userGrant := fixture.send(t, http.MethodPost, "/api/v1/grants", `{"user":"ADA","resource":"dashboards","expires_at":"`+later.Format(time.RFC3339)+`"}`)
	require.Equal(t, http.StatusCreated, userGrant.Code, userGrant.Body.String())
	reply := decodeReply[map[string]any](t, userGrant.Body)
	assert.NotEmpty(t, reply["id"])
	assert.Equal(t, map[string]any{"name": "dashboards", "url": "dash.example.test/"}, reply["resource"])
	assert.Equal(t, "ada", reply["user"])
	assert.NotContains(t, reply, "group")
	assert.Equal(t, later.Format(time.RFC3339), reply["expires_at"])
	assert.NotEmpty(t, reply["created_at"])

	groupGrant := fixture.send(t, http.MethodPost, "/api/v1/grants", `{"group":"editors","resource":"dashboards"}`)
	require.Equal(t, http.StatusCreated, groupGrant.Code, groupGrant.Body.String())
	reply = decodeReply[map[string]any](t, groupGrant.Body)
	assert.Equal(t, "editors", reply["group"])
	assert.NotContains(t, reply, "user")
	assert.NotContains(t, reply, "expires_at")

	tests := []struct {
		name  string
		token string
		body  string
		want  int
	}{
		{name: "no token", body: `{"user":"ada","resource":"dashboards"}`, want: http.StatusUnauthorized},
		{name: "no subject", token: accessAdminToken, body: `{"resource":"dashboards"}`, want: http.StatusBadRequest},
		{name: "user and group", token: accessAdminToken, body: `{"user":"ada","group":"admins","resource":"dashboards"}`, want: http.StatusBadRequest},
		{name: "bad login", token: accessAdminToken, body: `{"user":"bad login","resource":"dashboards"}`, want: http.StatusBadRequest},
		{name: "bad group", token: accessAdminToken, body: `{"group":"-x","resource":"dashboards"}`, want: http.StatusBadRequest},
		{name: "no resource", token: accessAdminToken, body: `{"user":"bob"}`, want: http.StatusBadRequest},
		{name: "past expiry", token: accessAdminToken, body: `{"user":"bob","resource":"dashboards","expires_at":"2001-01-01T00:00:00Z"}`, want: http.StatusBadRequest},
		{name: "zero expiry", token: accessAdminToken, body: `{"user":"bob","resource":"dashboards","expires_at":"0001-01-01T00:00:00Z"}`, want: http.StatusBadRequest},
		{name: "expiry not RFC 3339", token: accessAdminToken, body: `{"user":"bob","resource":"dashboards","expires_at":"tomorrow"}`, want: http.StatusBadRequest},
		{name: "unknown user", token: accessAdminToken, body: `{"user":"nobody","resource":"dashboards"}`, want: http.StatusNotFound},
		{name: "unknown resource", token: accessAdminToken, body: `{"user":"bob","resource":"missing"}`, want: http.StatusNotFound},
		{name: "duplicate user grant", token: accessAdminToken, body: `{"user":"ada","resource":"dashboards"}`, want: http.StatusConflict},
		{name: "duplicate group grant", token: accessAdminToken, body: `{"group":"editors","resource":"dashboards"}`, want: http.StatusConflict},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := fixture.sendAs(t, tt.token, "application/json", http.MethodPost, "/api/v1/grants", tt.body)
			require.Equal(t, tt.want, rec.Code, rec.Body.String())
			assert.Contains(t, rec.Header().Get("Content-Type"), "application/problem+json")
		})
	}
}

func TestListGrants(t *testing.T) {
	fixture := newAccessFixture(t)
	fixture.createResource(t, "dashboards", "https://dash.example.test/")
	fixture.createResource(t, "mcp", "https://dash.example.test/mcp")
	fixture.grant(t, `{"user":"ada","resource":"mcp"}`)
	fixture.grant(t, `{"user":"bob","resource":"dashboards"}`)
	fixture.grant(t, `{"group":"editors","resource":"dashboards"}`)

	tests := []struct {
		name  string
		query string
		want  int
		rows  []string
	}{
		{name: "every grant", want: http.StatusOK, rows: []string{"dashboards dash.example.test/ bob", "dashboards dash.example.test/ editors", "mcp dash.example.test/mcp ada"}},
		{name: "one user", query: "?user=ada", want: http.StatusOK, rows: []string{"mcp dash.example.test/mcp ada"}},
		{name: "one resource", query: "?resource=dashboards", want: http.StatusOK, rows: []string{"dashboards dash.example.test/ bob", "dashboards dash.example.test/ editors"}},
		{name: "user and resource", query: "?user=ada&resource=dashboards", want: http.StatusOK, rows: []string{}},
		{name: "unknown user", query: "?user=nobody", want: http.StatusNotFound},
		{name: "unknown resource", query: "?resource=missing", want: http.StatusNotFound},
		{name: "bad login", query: "?user=bad%20login", want: http.StatusBadRequest},
		{name: "bad resource", query: "?resource=-x", want: http.StatusBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := fixture.send(t, http.MethodGet, "/api/v1/grants"+tt.query, "")
			require.Equal(t, tt.want, rec.Code, rec.Body.String())
			if tt.want != http.StatusOK {
				assert.Contains(t, rec.Header().Get("Content-Type"), "application/problem+json")
				return
			}
			listed := decodeReply[struct{ Grants []grantText }](t, rec.Body)
			rows := []string{}
			for _, grant := range listed.Grants {
				rows = append(rows, grant.Resource.Name+" "+grant.Resource.URL+" "+grant.User+grant.Group)
				assert.NotEmpty(t, grant.CreatedAt)
			}
			assert.Equal(t, tt.rows, rows)
		})
	}
	require.Equal(t, http.StatusUnauthorized, fixture.sendAs(t, "", "", http.MethodGet, "/api/v1/grants", "").Code)
}

func TestRevokeGrant(t *testing.T) {
	fixture := newAccessFixture(t)
	fixture.createResource(t, "dashboards", "https://dash.example.test/")
	grant := fixture.grant(t, `{"user":"ada","resource":"dashboards"}`)
	path := "/api/v1/grants/" + grant.ID

	require.Equal(t, http.StatusUnauthorized, fixture.sendAs(t, "", "", http.MethodDelete, path, "").Code)
	revoked := fixture.send(t, http.MethodDelete, path, "")
	require.Equal(t, http.StatusNoContent, revoked.Code)
	assert.Empty(t, revoked.Body.String())
	require.Equal(t, http.StatusNotFound, fixture.send(t, http.MethodDelete, path, "").Code)
	require.Equal(t, http.StatusNotFound, fixture.send(t, http.MethodDelete, "/api/v1/grants/not-a-uuid", "").Code)
	listed := fixture.send(t, http.MethodGet, "/api/v1/grants", "")
	assert.JSONEq(t, `{"grants":[]}`, listed.Body.String())
}

func TestAccessRoutesWithoutTheServiceAre503(t *testing.T) {
	router := mustRouter(t, &memRepo{}, accessAdminToken)
	for _, target := range []struct{ method, path string }{
		{http.MethodPost, "/api/v1/resources"},
		{http.MethodGet, "/api/v1/resources"},
		{http.MethodDelete, "/api/v1/resources/dashboards"},
		{http.MethodPost, "/api/v1/grants"},
		{http.MethodGet, "/api/v1/grants"},
		{http.MethodDelete, "/api/v1/grants/" + access.NewGrantID().String()},
	} {
		rec := sendAccess(t, router, accessAdminToken, "application/json", target.method, target.path, `{}`)
		require.Equal(t, http.StatusServiceUnavailable, rec.Code, target.path)
	}
}

// accessFixture is a router with the access routes, the users ada and bob, and no resource.
type accessFixture struct {
	router http.Handler
}

func newAccessFixture(t *testing.T) accessFixture {
	t.Helper()
	accounts := &memRepo{}
	repo := accesstest.NewRepository()
	for _, raw := range []string{"ada", "bob"} {
		account := users.User{ID: users.NewID(), Login: mustLogin(t, raw), CreatedAt: time.Now().UTC()}
		accounts.put(account)
		repo.AddUser(account.ID, account.Login)
	}
	grants := access.NewService(repo, users.NewService(accounts))
	router := forwardRouter(t, accounts, sessions.NewService(newMemSessions()), newMemGroups(), sessions.Domain{}, PublicURL{}, WithURLGrants(grants), WithAccessAdmin(grants))
	return accessFixture{router: router}
}

func (f accessFixture) send(t *testing.T, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	return sendAccess(t, f.router, accessAdminToken, "application/json", method, path, body)
}

func (f accessFixture) sendAs(t *testing.T, token, contentType, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	return sendAccess(t, f.router, token, contentType, method, path, body)
}

func (f accessFixture) createResource(t *testing.T, name, rawURL string) {
	t.Helper()
	rec := f.send(t, http.MethodPost, "/api/v1/resources", `{"name":"`+name+`","url":"`+rawURL+`"}`)
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
}

// grantText is a grant reply as the client reads it.
type grantText struct {
	ID       string `json:"id"`
	Resource struct {
		Name string `json:"name"`
		URL  string `json:"url"`
	} `json:"resource"`
	User      string `json:"user"`
	Group     string `json:"group"`
	ExpiresAt string `json:"expires_at"`
	CreatedAt string `json:"created_at"`
}

func (f accessFixture) grant(t *testing.T, body string) grantText {
	t.Helper()
	rec := f.send(t, http.MethodPost, "/api/v1/grants", body)
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	return decodeReply[grantText](t, rec.Body)
}

// sendAccess sends no Authorization header for an empty token and no Content-Type for an empty type.
func sendAccess(t *testing.T, router http.Handler, token, contentType, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), method, path, strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

func decodeReply[T any](t *testing.T, body io.Reader) T {
	t.Helper()
	var reply T
	require.NoError(t, json.NewDecoder(body).Decode(&reply))
	return reply
}
