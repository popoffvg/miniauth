package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"mime"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/popoffvg/miniauth/internal/user"
)

func TestPasswordFieldPrintsRedacted(t *testing.T) {
	field := passwordField{raw: "correct horse"}
	printed := []string{
		fmt.Sprint(field),
		fmt.Sprintf("%#v", field),
		field.String(),
	}
	for _, text := range printed {
		if text != "redacted" || strings.Contains(text, "horse") {
			t.Fatalf("print = %q, want redacted", text)
		}
	}
	encoded, err := json.Marshal(field)
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) != `"redacted"` {
		t.Fatalf("json = %s", encoded)
	}
}

func TestCreateUser(t *testing.T) {
	t.Parallel()
	repo := &memRepo{}
	h := newHarness(t, repo)
	const password = "correct horse battery staple"
	body := `{"login":"Ada","password":"` + password + `"}`

	rec := h.post(t, "", body, "application/json")
	assertProblem(t, rec, http.StatusUnauthorized)
	if rec.Header().Get("WWW-Authenticate") != "Bearer" {
		t.Fatalf("WWW-Authenticate = %q", rec.Header().Get("WWW-Authenticate"))
	}
	assertNoSecret(t, rec.Body.String(), password, h.token)
	if h.logs.Len() != 0 {
		t.Fatalf("unauthorized request was logged: %s", h.logs.String())
	}

	rec = h.post(t, "wrong-token", body, "application/json")
	assertProblem(t, rec, http.StatusUnauthorized)
	assertNoSecret(t, rec.Body.String(), password, h.token, "wrong-token")

	rec = h.postQuery(t, password, h.token)
	assertProblem(t, rec, http.StatusUnauthorized)
	assertNoSecret(t, rec.Body.String(), password, h.token)

	rec = h.post(t, h.token, body, "text/plain")
	assertProblem(t, rec, http.StatusUnsupportedMediaType)

	rec = h.post(t, h.token, `{`, "application/json")
	assertProblem(t, rec, http.StatusBadRequest)

	rec = h.post(t, h.token, `{"login":"bad login","password":"x"}`, "application/json")
	assertProblem(t, rec, http.StatusBadRequest)
	if strings.Contains(rec.Body.String(), "bad login") {
		t.Fatal("invalid login was echoed")
	}

	rec = h.post(t, h.token, `{"login":"ada","password":""}`, "application/json")
	assertProblem(t, rec, http.StatusBadRequest)

	long := strings.Repeat("a", user.MaxPasswordBytes+1)
	rec = h.post(t, h.token, `{"login":"ada","password":"`+long+`"}`, "application/json")
	assertProblem(t, rec, http.StatusBadRequest)

	rec = h.post(t, h.token, `{"login":"ada","password":"x","extra":"y"}`, "application/json")
	assertProblem(t, rec, http.StatusBadRequest)

	huge := `{"login":"ada","password":"` + strings.Repeat("a", maxCreateUserBody) + `"}`
	rec = h.post(t, h.token, huge, "application/json")
	assertProblem(t, rec, http.StatusRequestEntityTooLarge)
	if h.logs.Len() != 0 {
		t.Fatalf("rejected request was logged: %s", h.logs.String())
	}

	rec = h.post(t, h.token, body, "application/json; charset=utf-8")
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: got %d, body contains secret: %v", rec.Code, strings.Contains(rec.Body.String(), password))
	}
	mediaType, _, err := mime.ParseMediaType(rec.Header().Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		t.Fatalf("content type = %q", rec.Header().Get("Content-Type"))
	}
	var created createdUser
	if err = json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if created.Login != "ada" {
		t.Fatalf("login = %s", created.Login)
	}
	if _, err = created.ID.Bytes(); err != nil {
		t.Fatal(err)
	}
	assertNoSecret(t, rec.Body.String(), password)
	if strings.Contains(rec.Body.String(), "password") || strings.Contains(rec.Body.String(), "$argon2id$") {
		t.Fatal("response includes a password field or a hash")
	}

	stored, ok := repo.get("ada")
	if !ok {
		t.Fatal("user was not stored")
	}
	if stored.identity.Kind != user.KindPassword {
		t.Fatalf("kind = %s", stored.identity.Kind)
	}
	encoded := stored.identity.Secret.Encoded()
	if !strings.HasPrefix(encoded, "$argon2id$") || strings.Contains(encoded, password) {
		t.Fatal("stored secret is not an argon2id hash of the password")
	}
	pw, err := user.NewPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	matches, err := stored.identity.Secret.Matches(pw)
	if err != nil || !matches {
		t.Fatalf("Matches() = %v, %v", matches, err)
	}

	rec = h.post(t, h.token, body, "application/json")
	assertProblem(t, rec, http.StatusConflict)
	assertNoSecret(t, rec.Body.String(), password, encoded)
	if repo.count() != 1 {
		t.Fatalf("users = %d, want 1", repo.count())
	}
	if h.logs.Len() != 0 {
		t.Fatalf("create was logged: %s", h.logs.String())
	}
}

func TestCreateUserHidesAStoreFailure(t *testing.T) {
	h := newHarness(t, failRepo{})
	const password = "correct horse battery staple"
	rec := h.post(t, h.token, `{"login":"ada","password":"`+password+`"}`, "application/json")
	assertProblem(t, rec, http.StatusInternalServerError)
	assertNoSecret(t, rec.Body.String(), password)
	if strings.Contains(rec.Body.String(), "database is down") {
		t.Fatal("internal error reached the response")
	}
	if !strings.Contains(h.logs.String(), "database is down") {
		t.Fatal("store failure was not logged")
	}
	assertNoSecret(t, h.logs.String(), password, h.token)
}

type harness struct {
	router *Router
	token  string
	logs   *bytes.Buffer
}

func newHarness(t *testing.T, repo user.Repository) *harness {
	t.Helper()
	const token = "bootstrap-token-for-tests"
	sum := sha256.Sum256([]byte(token))
	hash, err := ParseAdminTokenHash(hex.EncodeToString(sum[:]))
	if err != nil {
		t.Fatal(err)
	}
	logs := &bytes.Buffer{}
	logger := slog.New(slog.NewTextHandler(logs, nil))
	return &harness{
		router: NewRouter(user.NewUsers(repo), hash, logger),
		token:  token,
		logs:   logs,
	}
}

func (h *harness) post(t *testing.T, token, body, contentType string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v1/users", strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	rec := httptest.NewRecorder()
	h.router.ServeHTTP(rec, req)
	return rec
}

func (h *harness) postQuery(t *testing.T, password, token string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v1/users", strings.NewReader(`{"login":"ada","password":"unused"}`))
	query := url.Values{}
	query.Set("password", password)
	query.Set("access_token", token)
	req.URL.RawQuery = query.Encode()
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.router.ServeHTTP(rec, req)
	return rec
}

func assertProblem(t *testing.T, rec *httptest.ResponseRecorder, status int) {
	t.Helper()
	if rec.Code != status {
		t.Fatalf("status = %d, want %d", rec.Code, status)
	}
	mediaType, _, err := mime.ParseMediaType(rec.Header().Get("Content-Type"))
	if err != nil || mediaType != "application/problem+json" {
		t.Fatalf("content type = %q", rec.Header().Get("Content-Type"))
	}
	var problem Problem
	if err = json.Unmarshal(rec.Body.Bytes(), &problem); err != nil {
		t.Fatal(err)
	}
	if problem.Type != "about:blank" || problem.Title != http.StatusText(status) || problem.Status != status || problem.Detail == "" {
		t.Fatalf("problem = %+v", problem)
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("Cache-Control = %q", rec.Header().Get("Cache-Control"))
	}
}

func assertNoSecret(t *testing.T, text string, secrets ...string) {
	t.Helper()
	for _, secret := range secrets {
		if secret != "" && strings.Contains(text, secret) {
			t.Fatal("output contains a secret")
		}
	}
}

type storedUser struct {
	account  user.User
	identity user.Identity
}

type memRepo struct {
	mu      sync.Mutex
	byLogin map[user.Login]storedUser
}

func (m *memRepo) Create(_ context.Context, account user.User, identity user.Identity) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.byLogin == nil {
		m.byLogin = map[user.Login]storedUser{}
	}
	if _, ok := m.byLogin[account.Login]; ok {
		return user.ErrLoginTaken
	}
	m.byLogin[account.Login] = storedUser{account: account, identity: identity}
	return nil
}

func (m *memRepo) get(login user.Login) (storedUser, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	stored, ok := m.byLogin[login]
	return stored, ok
}

func (m *memRepo) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.byLogin)
}

type failRepo struct{}

func (failRepo) Create(context.Context, user.User, user.Identity) error {
	return errors.New("database is down")
}
