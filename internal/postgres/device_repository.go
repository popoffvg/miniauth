package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/popoffvg/miniauth/internal/devices"
	"github.com/popoffvg/miniauth/internal/postgres/sqlcgen"
	"github.com/popoffvg/miniauth/internal/sessions"
	"github.com/popoffvg/miniauth/internal/users"
)

// StartOnDevice upserts the device and replaces the session of (user, device) in one transaction.
// The device cookie hash and the session hash are stored. The cookie values are not.
func (r *SessionRepository) StartOnDevice(ctx context.Context, session sessions.Session, hash sessions.Hash, visit devices.Visit) (devices.ID, error) {
	if r.begin == nil {
		return devices.ID{}, errors.New("postgres: session repository cannot begin a transaction")
	}
	userID := pgUUIDBytes(session.UserID.Bytes())
	var deviceID pgtype.UUID
	err := pgx.BeginFunc(ctx, r.begin, func(tx pgx.Tx) error {
		q := r.q.WithTx(tx)
		var err error
		deviceID, err = q.UpsertDevice(ctx, sqlcgen.UpsertDeviceParams{
			ID:         pgUUIDBytes(visit.NewID.Bytes()),
			UserID:     userID,
			SecretHash: visit.TokenHash[:],
			Name:       visit.Name.String(),
			SeenAt:     pgTime(visit.At),
		})
		if err != nil {
			return sessionError("upsert device", err)
		}
		err = q.UpsertDeviceSession(ctx, sqlcgen.UpsertDeviceSessionParams{
			SecretHash: hash[:],
			UserID:     userID,
			DeviceID:   deviceID,
			Factors:    int32(session.Factors),
			AuthAt:     pgTime(session.AuthAt),
			ExpiresAt:  pgTime(session.ExpiresAt),
		})
		if err != nil {
			return sessionError("replace device session", err)
		}
		return nil
	})
	if err != nil {
		return devices.ID{}, fmt.Errorf("postgres: start session on device: %w", err)
	}
	if !deviceID.Valid {
		return devices.ID{}, errors.New("postgres: upsert device returned no id")
	}
	return devices.IDFromBytes(deviceID.Bytes), nil
}

// ListDevices returns the devices of userID, the most recent first.
func (r *SessionRepository) ListDevices(ctx context.Context, userID users.ID) ([]devices.Device, error) {
	rows, err := r.q.ListDevices(ctx, pgUUIDBytes(userID.Bytes()))
	if err != nil {
		return nil, sessionError("list devices", err)
	}
	list := make([]devices.Device, 0, len(rows))
	for _, row := range rows {
		if !row.ID.Valid || !row.UserID.Valid || !row.FirstSeen.Valid || !row.LastSeen.Valid {
			return nil, errors.New("postgres: device row is incomplete")
		}
		list = append(list, devices.Device{
			ID:        devices.IDFromBytes(row.ID.Bytes),
			UserID:    users.IDFromBytes(row.UserID.Bytes),
			Name:      devices.ParseName(row.Name),
			FirstSeen: row.FirstSeen.Time.UTC(),
			LastSeen:  row.LastSeen.Time.UTC(),
		})
	}
	return list, nil
}

// SignOutDevice deletes the session of a device of userID.
// A device of another user is devices.ErrNotFound.
func (r *SessionRepository) SignOutDevice(ctx context.Context, userID users.ID, deviceID devices.ID) error {
	owned, err := r.q.DeviceOwned(ctx, sqlcgen.DeviceOwnedParams{
		ID:     pgUUIDBytes(deviceID.Bytes()),
		UserID: pgUUIDBytes(userID.Bytes()),
	})
	if err != nil {
		return sessionError("find device", err)
	}
	if !owned {
		return devices.ErrNotFound
	}
	err = r.q.DeleteDeviceSession(ctx, sqlcgen.DeleteDeviceSessionParams{
		UserID:   pgUUIDBytes(userID.Bytes()),
		DeviceID: pgUUIDBytes(deviceID.Bytes()),
	})
	if err != nil {
		return sessionError("delete device session", err)
	}
	return nil
}

// ForgetDevice deletes a device of userID. The foreign key deletes its session.
// A device of another user is devices.ErrNotFound.
func (r *SessionRepository) ForgetDevice(ctx context.Context, userID users.ID, deviceID devices.ID) error {
	n, err := r.q.DeleteDevice(ctx, sqlcgen.DeleteDeviceParams{
		ID:     pgUUIDBytes(deviceID.Bytes()),
		UserID: pgUUIDBytes(userID.Bytes()),
	})
	if err != nil {
		return sessionError("delete device", err)
	}
	if n == 0 {
		return devices.ErrNotFound
	}
	return nil
}

func deviceIDFrom(id pgtype.UUID) devices.ID {
	if !id.Valid {
		return devices.ID{}
	}
	return devices.IDFromBytes(id.Bytes)
}
