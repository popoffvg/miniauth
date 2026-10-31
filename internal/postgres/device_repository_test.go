package postgres_test

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/popoffvg/miniauth/internal/devices"
	"github.com/popoffvg/miniauth/internal/loginflow"
	"github.com/popoffvg/miniauth/internal/postgres"
	"github.com/popoffvg/miniauth/internal/postgres/postgrestest"
	"github.com/popoffvg/miniauth/internal/postgres/sqlcgen"
	"github.com/popoffvg/miniauth/internal/sessions"
	"github.com/popoffvg/miniauth/internal/users"
)

const (
	firefoxAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:131.0) Gecko/20100101 Firefox/131.0"
	chromeAgent  = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"
)

func TestOneSessionPerDevice(t *testing.T) {
	ctx := t.Context()
	pool, err := postgres.Open(ctx, postgrestest.NewDatabase(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if err = postgres.Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	accounts := users.NewService(postgres.NewUserRepository(pool))
	ada := createAccount(t, accounts, "ada")
	bea := createAccount(t, accounts, "bea")
	svc := sessions.NewService(postgres.NewSessionRepository(pool))
	q := sqlcgen.New(pool)

	first, laptopCookie, laptop := loginOnDevice(t, svc, ada.ID, firefoxAgent, nil)
	second, _, again := loginOnDevice(t, svc, ada.ID, firefoxAgent, laptopCookie)
	if again.DeviceID != laptop.DeviceID {
		t.Fatal("a second login from one browser made a new device")
	}
	if n := count(t, q.CountSessions); n != 1 {
		t.Fatalf("sessions after two logins from one browser = %d, want 1", n)
	}
	if n := count(t, q.CountDevices); n != 1 {
		t.Fatalf("devices = %d, want 1", n)
	}
	if _, _, err = svc.Open(ctx, first); !errors.Is(err, sessions.ErrNotFound) {
		t.Fatalf("replaced session = %v", err)
	}
	opened, _, err := svc.Open(ctx, second)
	if err != nil {
		t.Fatal(err)
	}
	if opened.DeviceID != laptop.DeviceID {
		t.Fatal("session lost its device")
	}

	phoneSession, _, phone := loginOnDevice(t, svc, ada.ID, chromeAgent, nil)
	beaSession, _, beaLaptop := loginOnDevice(t, svc, bea.ID, firefoxAgent, laptopCookie)
	if beaLaptop.DeviceID == laptop.DeviceID {
		t.Fatal("two users share one device row")
	}

	list, err := svc.Devices(ctx, ada.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 {
		t.Fatalf("devices of ada = %d, want 2", len(list))
	}
	names := map[string]bool{}
	for _, device := range list {
		names[device.Name.String()] = true
	}
	if !names["Firefox on macOS"] || !names["Chrome on Windows"] {
		t.Fatalf("names = %v", names)
	}

	if err = svc.SignOutDevice(ctx, ada.ID, phone.DeviceID); err != nil {
		t.Fatal(err)
	}
	if _, _, err = svc.Open(ctx, phoneSession); !errors.Is(err, sessions.ErrNotFound) {
		t.Fatalf("signed-out device = %v", err)
	}
	if _, _, err = svc.Open(ctx, second); err != nil {
		t.Fatalf("other device after sign-out = %v", err)
	}

	if err = svc.SignOutDevice(ctx, ada.ID, beaLaptop.DeviceID); !errors.Is(err, devices.ErrNotFound) {
		t.Fatalf("sign out a foreign device = %v", err)
	}
	if err = svc.ForgetDevice(ctx, ada.ID, beaLaptop.DeviceID); !errors.Is(err, devices.ErrNotFound) {
		t.Fatalf("forget a foreign device = %v", err)
	}
	if _, _, err = svc.Open(ctx, beaSession); err != nil {
		t.Fatalf("foreign session = %v", err)
	}

	if err = svc.ForgetDevice(ctx, ada.ID, laptop.DeviceID); err != nil {
		t.Fatal(err)
	}
	if _, _, err = svc.Open(ctx, second); !errors.Is(err, sessions.ErrNotFound) {
		t.Fatalf("session of a forgotten device = %v", err)
	}
	list, err = svc.Devices(ctx, ada.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].ID != phone.DeviceID {
		t.Fatalf("devices after forget = %+v", list)
	}

	token, err := devices.ParseToken(laptopCookie.Value)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := q.GetStoredDeviceHash(ctx, pgtype.UUID{Bytes: beaLaptop.DeviceID.Bytes(), Valid: true})
	if err != nil {
		t.Fatal(err)
	}
	hash := token.Hash()
	if !bytes.Equal(stored, hash[:]) {
		t.Fatal("devices table did not store the SHA-256 of the cookie")
	}
}

func loginOnDevice(t *testing.T, svc *sessions.Service, user users.ID, agent string, device *http.Cookie) (sessions.ID, *http.Cookie, sessions.Session) {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/login", nil)
	req.Header.Set("User-Agent", agent)
	if device != nil {
		req.AddCookie(device)
	}
	rec := httptest.NewRecorder()
	id, session, err := svc.StartOnDevice(t.Context(), rec, req, sessions.Domain{}, user, loginflow.Factors(loginflow.FactorPassword))
	if err != nil {
		t.Fatal(err)
	}
	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == sessions.DeviceCookieName {
			return id, &http.Cookie{Name: cookie.Name, Value: cookie.Value}, session
		}
	}
	t.Fatal("no device cookie")
	return sessions.ID{}, nil, sessions.Session{}
}

func count(t *testing.T, query func(ctx context.Context) (int64, error)) int64 {
	t.Helper()
	n, err := query(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	return n
}
