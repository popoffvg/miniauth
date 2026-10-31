package sessions

import (
	"context"
	"errors"
	"time"

	"github.com/popoffvg/miniauth/internal/loginflow"
	"github.com/popoffvg/miniauth/internal/users"
)

// Repository stores sessions.
// Create stores the hash, never the session id.
// Extend writes expires_at only when the stored expiry is at or before extendBefore.
// ConfirmAuth writes auth_at only when the session belongs to userID.
type Repository interface {
	Create(ctx context.Context, session Session, hash Hash) error
	Find(ctx context.Context, hash Hash) (Session, Hash, error)
	Extend(ctx context.Context, hash Hash, expiresAt, extendBefore time.Time) (bool, error)
	ConfirmAuth(ctx context.Context, hash Hash, userID users.ID, authAt time.Time) (bool, error)
	Delete(ctx context.Context, hash Hash) error
	DeleteUser(ctx context.Context, userID users.ID) error
}

// Service issues and reads sessions.
type Service struct {
	repo    Repository
	devices DeviceRepository
	now     func() time.Time
}

// NewService returns a service that reads the clock from time.Now.
// When repo is also a DeviceRepository, the device operations use it. Otherwise they return ErrNoDeviceStore.
func NewService(repo Repository) *Service {
	deviceRepo, _ := repo.(DeviceRepository)
	return &Service{repo: repo, devices: deviceRepo, now: time.Now}
}

// Start stores a session for userID and returns its id.
// The id is not stored. The hash is stored.
func (s *Service) Start(ctx context.Context, userID users.ID, factors loginflow.Factors) (ID, Session, error) {
	if s == nil || s.repo == nil {
		return ID{}, Session{}, errors.New("sessions: repository is missing")
	}
	if userID == (users.ID{}) {
		return ID{}, Session{}, ErrUnknownUser
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
	if err := s.repo.Create(ctx, session, id.Hash()); err != nil {
		return ID{}, Session{}, err
	}
	return id, session, nil
}

// Open returns the session for id.
// The second result is true when this call wrote a new expires_at.
// A write happens at most once per ExtendEvery.
func (s *Service) Open(ctx context.Context, id ID) (Session, bool, error) {
	session, err := s.current(ctx, id)
	if err != nil {
		return Session{}, false, err
	}
	now := s.clock()
	if !due(session.ExpiresAt, now) {
		return session, false, nil
	}
	next := now.Add(Lifetime)
	wrote, err := s.repo.Extend(ctx, id.Hash(), next, extendBefore(now))
	if err != nil {
		return Session{}, false, err
	}
	if !wrote {
		again, err := s.current(ctx, id)
		return again, false, err
	}
	session.ExpiresAt = next
	return session, true, nil
}

// Logout deletes the session for id.
// A missing id is success.
func (s *Service) Logout(ctx context.Context, id ID) error {
	if s == nil || s.repo == nil {
		return errors.New("sessions: repository is missing")
	}
	_, hash, err := s.fetch(ctx, id)
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	return s.repo.Delete(ctx, hash)
}

// LogoutEverywhere deletes every session of the user who holds id.
// An expired id does not delete the other sessions.
func (s *Service) LogoutEverywhere(ctx context.Context, id ID) error {
	session, err := s.current(ctx, id)
	if err != nil {
		return err
	}
	return s.repo.DeleteUser(ctx, session.UserID)
}

func (s *Service) current(ctx context.Context, id ID) (Session, error) {
	session, hash, err := s.fetch(ctx, id)
	if err != nil {
		return Session{}, err
	}
	if !session.ExpiresAt.After(s.clock()) {
		if err := s.repo.Delete(ctx, hash); err != nil {
			return Session{}, err
		}
		return Session{}, ErrNotFound
	}
	return session, nil
}

func (s *Service) fetch(ctx context.Context, id ID) (Session, Hash, error) {
	if s == nil || s.repo == nil {
		return Session{}, Hash{}, errors.New("sessions: repository is missing")
	}
	if id.isZero() {
		return Session{}, Hash{}, ErrNotFound
	}
	session, stored, err := s.repo.Find(ctx, id.Hash())
	if err != nil {
		return Session{}, Hash{}, err
	}
	if !id.Matches(stored) {
		return Session{}, Hash{}, ErrNotFound
	}
	return session, stored, nil
}

// clock returns UTC truncated to microseconds.
// PostgreSQL timestamptz stores microseconds.
func (s *Service) clock() time.Time {
	now := time.Now
	if s != nil && s.now != nil {
		now = s.now
	}
	return now().UTC().Truncate(time.Microsecond)
}
