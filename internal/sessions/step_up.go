package sessions

import (
	"context"
	"time"

	"github.com/popoffvg/miniauth/internal/users"
)

// StepUpAfter is the age of AuthAt after which a sensitive action asks for the password again.
const StepUpAfter = 10 * time.Minute

// NewServiceWithClock is NewService with the clock read from now.
func NewServiceWithClock(repo Repository, now func() time.Time) *Service {
	s := NewService(repo)
	s.now = now
	return s
}

// AuthRecent reports whether the last full login of session is newer than StepUpAfter.
func (s *Service) AuthRecent(session Session) bool {
	return session.AuthAt.After(s.clock().Add(-StepUpAfter))
}

// ConfirmAuth sets AuthAt of the session for id to now after a step-up of userID.
// A session of another user, or an expired one, is ErrNotFound.
func (s *Service) ConfirmAuth(ctx context.Context, id ID, userID users.ID) (Session, error) {
	session, err := s.current(ctx, id)
	if err != nil {
		return Session{}, err
	}
	if session.UserID != userID {
		return Session{}, ErrNotFound
	}
	now := s.clock()
	wrote, err := s.repo.ConfirmAuth(ctx, id.Hash(), userID, now)
	if err != nil {
		return Session{}, err
	}
	if !wrote {
		return Session{}, ErrNotFound
	}
	session.AuthAt = now
	return session, nil
}
