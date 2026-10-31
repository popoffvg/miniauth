package sessions

import (
	"context"
	"net/http"

	"github.com/popoffvg/miniauth/internal/devices"
	"github.com/popoffvg/miniauth/internal/loginflow"
	"github.com/popoffvg/miniauth/internal/users"
)

// DeviceRepository stores devices and the one session of each device.
// StartOnDevice upserts the device and replaces the session of (user, device) in one transaction.
// SignOutDevice and ForgetDevice return devices.ErrNotFound when the device is not the user's.
// ForgetDevice also deletes the session of the device.
type DeviceRepository interface {
	StartOnDevice(ctx context.Context, session Session, hash Hash, visit devices.Visit) (devices.ID, error)
	ListDevices(ctx context.Context, userID users.ID) ([]devices.Device, error)
	SignOutDevice(ctx context.Context, userID users.ID, deviceID devices.ID) error
	ForgetDevice(ctx context.Context, userID users.ID, deviceID devices.ID) error
}

// StartOnDevice starts a session for userID on the browser of r after a successful login.
// It reads the device cookie or makes a new one, replaces the session of that device,
// and writes both cookies to w.
func (s *Service) StartOnDevice(ctx context.Context, w http.ResponseWriter, r *http.Request, domain Domain, userID users.ID, factors loginflow.Factors) (ID, Session, error) {
	store, err := s.deviceStore()
	if err != nil {
		return ID{}, Session{}, err
	}
	if userID == (users.ID{}) {
		return ID{}, Session{}, ErrUnknownUser
	}
	token, ok := DeviceTokenFromRequest(r)
	if !ok {
		token, err = devices.NewToken()
		if err != nil {
			return ID{}, Session{}, err
		}
	}
	id, err := NewID()
	if err != nil {
		return ID{}, Session{}, err
	}
	now := s.clock()
	session := Session{
		UserID:    userID,
		Factors:   factors,
		AuthAt:    now,
		ExpiresAt: now.Add(Lifetime),
	}
	visit := devices.Visit{
		NewID:     devices.NewID(),
		TokenHash: token.Hash(),
		Name:      devices.NameFromUserAgent(r.UserAgent()),
		At:        now,
	}
	session.DeviceID, err = store.StartOnDevice(ctx, session, id.Hash(), visit)
	if err != nil {
		return ID{}, Session{}, err
	}
	SetDeviceCookie(w, token, domain, now)
	SetCookie(w, id, domain, now)
	return id, session, nil
}

// Devices returns the devices of userID, the most recent first.
func (s *Service) Devices(ctx context.Context, userID users.ID) ([]devices.Device, error) {
	store, err := s.deviceStore()
	if err != nil {
		return nil, err
	}
	return store.ListDevices(ctx, userID)
}

// SignOutDevice deletes the session of a device of userID. The device stays.
func (s *Service) SignOutDevice(ctx context.Context, userID users.ID, deviceID devices.ID) error {
	store, err := s.deviceStore()
	if err != nil {
		return err
	}
	return store.SignOutDevice(ctx, userID, deviceID)
}

// ForgetDevice deletes a device of userID and its session.
func (s *Service) ForgetDevice(ctx context.Context, userID users.ID, deviceID devices.ID) error {
	store, err := s.deviceStore()
	if err != nil {
		return err
	}
	return store.ForgetDevice(ctx, userID, deviceID)
}

func (s *Service) deviceStore() (DeviceRepository, error) {
	if s == nil || s.devices == nil {
		return nil, ErrNoDeviceStore
	}
	return s.devices, nil
}
