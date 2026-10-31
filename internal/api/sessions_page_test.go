package api

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/popoffvg/miniauth/internal/devices"
	"github.com/popoffvg/miniauth/internal/loginflow"
	"github.com/popoffvg/miniauth/internal/sessions"
	"github.com/popoffvg/miniauth/internal/users"
)

const (
	firefoxAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:131.0) Gecko/20100101 Firefox/131.0"
	chromeAgent  = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"
	publicOrigin = "https://id.example.test"
)

func TestSessionsPageListsTheDevices(t *testing.T) {
	page := newDevicePage(t)
	user := users.NewID()
	first := page.login(t, user, firefoxAgent, nil)
	again := page.login(t, user, firefoxAgent, first.device)
	page.login(t, user, chromeAgent, nil)
	page.login(t, users.NewID(), chromeAgent, nil)

	assert.Equal(t, first.deviceID, again.deviceID)
	assert.Equal(t, 3, page.repo.sessionCount())
	_, _, err := page.browser.Open(t.Context(), first.session)
	require.ErrorIs(t, err, sessions.ErrNotFound)

	rec := page.get(t, again.session)
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "text/html; charset=utf-8", rec.Header().Get("Content-Type"))
	assert.Contains(t, rec.Header().Get("Content-Security-Policy"), "frame-ancestors 'none'")
	body := rec.Body.String()
	assert.Contains(t, body, "Firefox on macOS")
	assert.Contains(t, body, "Chrome on Windows")
	assert.Equal(t, 1, strings.Count(body, "(this device)"))
	assert.Equal(t, 2, strings.Count(body, "/signout"))
	assert.Contains(t, body, "/sessions/"+again.deviceID.String()+"/forget")
	assert.NotContains(t, body, again.session.CookieValue())
	assert.NotContains(t, body, again.device.Value)
	assert.NotContains(t, body, "<script")
}

func TestSessionsPageWithoutASession(t *testing.T) {
	page := newDevicePage(t)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, sessionsPagePath, nil)
	req.Header.Set("Accept", "text/html")
	rec := httptest.NewRecorder()
	page.router.ServeHTTP(rec, req)
	require.Equal(t, http.StatusFound, rec.Code)
	assert.Equal(t, publicOrigin+"/login?return=https%3A%2F%2Fid.example.test%2Fsessions", rec.Header().Get("Location"))

	req = httptest.NewRequestWithContext(t.Context(), http.MethodGet, sessionsPagePath, nil)
	req.Header.Set("Accept", "application/json")
	rec = httptest.NewRecorder()
	page.router.ServeHTTP(rec, req)
	require.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestSignOutDeviceKeepsTheOtherDevice(t *testing.T) {
	page := newDevicePage(t)
	user := users.NewID()
	laptop := page.login(t, user, firefoxAgent, nil)
	phone := page.login(t, user, chromeAgent, nil)

	rec := page.post(t, "/sessions/"+phone.deviceID.String()+"/signout", laptop.session, publicOrigin)
	require.Equal(t, http.StatusSeeOther, rec.Code)
	assert.Equal(t, sessionsPagePath, rec.Header().Get("Location"))
	assert.Empty(t, rec.Header().Values("Set-Cookie"))

	_, _, err := page.browser.Open(t.Context(), phone.session)
	require.ErrorIs(t, err, sessions.ErrNotFound)
	_, _, err = page.browser.Open(t.Context(), laptop.session)
	require.NoError(t, err)
	list, err := page.browser.Devices(t.Context(), user)
	require.NoError(t, err)
	assert.Len(t, list, 2)

	rec = page.post(t, "/sessions/"+laptop.deviceID.String()+"/signout", laptop.session, publicOrigin)
	require.Equal(t, http.StatusSeeOther, rec.Code)
	cleared := mustParseSetCookie(t, rec)
	assert.Equal(t, sessions.CookieName, cleared.Name)
	assert.Negative(t, cleared.MaxAge)
}

func TestForgetDeviceDeletesTheDeviceAndItsSession(t *testing.T) {
	page := newDevicePage(t)
	user := users.NewID()
	laptop := page.login(t, user, firefoxAgent, nil)
	phone := page.login(t, user, chromeAgent, nil)

	rec := page.post(t, "/sessions/"+phone.deviceID.String()+"/forget", laptop.session, publicOrigin)
	require.Equal(t, http.StatusSeeOther, rec.Code)

	_, _, err := page.browser.Open(t.Context(), phone.session)
	require.ErrorIs(t, err, sessions.ErrNotFound)
	_, _, err = page.browser.Open(t.Context(), laptop.session)
	require.NoError(t, err)
	list, err := page.browser.Devices(t.Context(), user)
	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.Equal(t, laptop.deviceID, list[0].ID)
}

func TestDeviceChangeRefusesAForeignDevice(t *testing.T) {
	page := newDevicePage(t)
	mine := page.login(t, users.NewID(), firefoxAgent, nil)
	other := page.login(t, users.NewID(), chromeAgent, nil)

	for _, action := range []string{"signout", "forget"} {
		rec := page.post(t, "/sessions/"+other.deviceID.String()+"/"+action, mine.session, publicOrigin)
		require.Equal(t, http.StatusNotFound, rec.Code, action)
		rec = page.post(t, "/sessions/not-a-device/"+action, mine.session, publicOrigin)
		require.Equal(t, http.StatusNotFound, rec.Code, action)
	}
	_, _, err := page.browser.Open(t.Context(), other.session)
	require.NoError(t, err)
}

func TestDeviceChangeRefusesABadOrigin(t *testing.T) {
	page := newDevicePage(t)
	user := users.NewID()
	laptop := page.login(t, user, firefoxAgent, nil)
	phone := page.login(t, user, chromeAgent, nil)

	for _, action := range []string{"signout", "forget"} {
		path := "/sessions/" + phone.deviceID.String() + "/" + action
		for _, origin := range []string{"", "https://evil.example.test", "http://id.example.test", "null"} {
			rec := page.post(t, path, laptop.session, origin)
			require.Equal(t, http.StatusForbidden, rec.Code, "%s from %q", action, origin)
		}
		rec := page.post(t, path, sessions.ID{}, publicOrigin)
		require.Equal(t, http.StatusUnauthorized, rec.Code, action)
	}
	_, _, err := page.browser.Open(t.Context(), phone.session)
	require.NoError(t, err)
}

func TestLogoutKeepsTheDeviceCookie(t *testing.T) {
	page := newDevicePage(t)
	laptop := page.login(t, users.NewID(), firefoxAgent, nil)
	rec := postCookie(t, page.router, "/logout", laptop.session)
	require.Equal(t, http.StatusNoContent, rec.Code)
	for _, header := range rec.Header().Values("Set-Cookie") {
		assert.NotContains(t, header, sessions.DeviceCookieName)
	}
}

type devicePage struct {
	repo    *memDeviceSessions
	browser *sessions.Service
	router  http.Handler
	domain  sessions.Domain
}

type deviceLogin struct {
	session  sessions.ID
	device   *http.Cookie
	deviceID devices.ID
}

func newDevicePage(t *testing.T) *devicePage {
	t.Helper()
	repo := newMemDeviceSessions()
	browser := sessions.NewService(repo)
	domain := mustDomain(t, ".example.test")
	router, err := NewRouter(users.NewService(&memRepo{}), browser, nil, domain, mustPublicURL(t, publicOrigin), hashToken(t, "bootstrap-token-for-tests"), &readyState{ok: true}, slog.New(slog.DiscardHandler))
	require.NoError(t, err)
	return &devicePage{repo: repo, browser: browser, router: router, domain: domain}
}

// login is what the login page does after a correct password.
func (p *devicePage) login(t *testing.T, user users.ID, agent string, device *http.Cookie) deviceLogin {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/login", nil)
	req.Header.Set("User-Agent", agent)
	if device != nil {
		req.AddCookie(device)
	}
	rec := httptest.NewRecorder()
	id, session, err := p.browser.StartOnDevice(t.Context(), rec, req, p.domain, user, loginflow.Factors(loginflow.FactorPassword))
	require.NoError(t, err)
	var written *http.Cookie
	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == sessions.DeviceCookieName {
			written = cookie
		}
	}
	require.NotNil(t, written)
	return deviceLogin{session: id, device: &http.Cookie{Name: written.Name, Value: written.Value}, deviceID: session.DeviceID}
}

func (p *devicePage) get(t *testing.T, id sessions.ID) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, sessionsPagePath, nil)
	req.Header.Set("Accept", "text/html")
	req.AddCookie(&http.Cookie{Name: sessions.CookieName, Value: id.CookieValue()})
	rec := httptest.NewRecorder()
	p.router.ServeHTTP(rec, req)
	return rec
}

// post sends no session cookie for the zero id and no Origin for an empty origin.
func (p *devicePage) post(t *testing.T, path string, id sessions.ID, origin string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, path, nil)
	if id != (sessions.ID{}) {
		req.AddCookie(&http.Cookie{Name: sessions.CookieName, Value: id.CookieValue()})
	}
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	rec := httptest.NewRecorder()
	p.router.ServeHTTP(rec, req)
	return rec
}

type memDevice struct {
	device devices.Device
	token  devices.TokenHash
}

// memDeviceSessions guards its devices with the mutex of memSessions.
type memDeviceSessions struct {
	*memSessions
	devices map[devices.ID]memDevice
}

func newMemDeviceSessions() *memDeviceSessions {
	return &memDeviceSessions{memSessions: newMemSessions(), devices: map[devices.ID]memDevice{}}
}

var _ sessions.DeviceRepository = (*memDeviceSessions)(nil)

func (m *memDeviceSessions) StartOnDevice(_ context.Context, session sessions.Session, hash sessions.Hash, visit devices.Visit) (devices.ID, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id := visit.NewID
	for known, row := range m.devices {
		if row.device.UserID == session.UserID && row.token == visit.TokenHash {
			id = known
		}
	}
	row, ok := m.devices[id]
	if !ok {
		row = memDevice{device: devices.Device{ID: id, UserID: session.UserID, FirstSeen: visit.At}, token: visit.TokenHash}
	}
	row.device.Name = visit.Name
	row.device.LastSeen = visit.At
	m.devices[id] = row
	m.deleteDeviceSession(session.UserID, id)
	session.DeviceID = id
	m.rows[hash] = session
	return id, nil
}

func (m *memDeviceSessions) ListDevices(_ context.Context, userID users.ID) ([]devices.Device, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var list []devices.Device
	for _, row := range m.devices {
		if row.device.UserID == userID {
			list = append(list, row.device)
		}
	}
	return list, nil
}

func (m *memDeviceSessions) SignOutDevice(_ context.Context, userID users.ID, deviceID devices.ID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	row, ok := m.devices[deviceID]
	if !ok || row.device.UserID != userID {
		return devices.ErrNotFound
	}
	m.deleteDeviceSession(userID, deviceID)
	return nil
}

func (m *memDeviceSessions) ForgetDevice(_ context.Context, userID users.ID, deviceID devices.ID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	row, ok := m.devices[deviceID]
	if !ok || row.device.UserID != userID {
		return devices.ErrNotFound
	}
	m.deleteDeviceSession(userID, deviceID)
	delete(m.devices, deviceID)
	return nil
}

func (m *memDeviceSessions) deleteDeviceSession(userID users.ID, deviceID devices.ID) {
	for hash, stored := range m.rows {
		if stored.UserID == userID && stored.DeviceID == deviceID {
			delete(m.rows, hash)
		}
	}
}

func (m *memDeviceSessions) sessionCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.rows)
}
