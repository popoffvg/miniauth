package users

import (
	"context"
	"errors"
	"time"
)

// Kind names how an identity proves the user.
type Kind string

const (
	// KindPassword is an argon2id password.
	KindPassword Kind = "password"
	// KindGoogle is a Google account. Its subject is the Google `sub` claim.
	KindGoogle Kind = "google"
	// KindTelegram is a Telegram account. Its subject is the decimal Telegram user id.
	KindTelegram Kind = "telegram"
)

// User is an account. It is comparable.
// A zero DisabledAt is an active account.
type User struct {
	ID         ID
	Login      Login
	CreatedAt  time.Time
	DisabledAt time.Time
}

// Disabled reports whether the account may no longer authenticate.
func (u User) Disabled() bool {
	return !u.DisabledAt.IsZero()
}

// Identity is one proof of a user. Secret is the argon2id PHC string for KindPassword.
// Subject is the outside account id for any other kind.
type Identity struct {
	ID        IdentityID
	UserID    ID
	Kind      Kind
	Secret    PasswordHash
	Subject   Subject
	CreatedAt time.Time
}

// Repository stores users and their identities.
// Create inserts the user and the identity together, and adds the user to the built-in group users.
// Create MUST return ErrLoginTaken when the login is already stored.
// Create MUST NOT write the password. It writes the PHC string.
// Find and FindByLogin MUST return ErrNotFound when no user matches.
type Repository interface {
	Create(ctx context.Context, account User, identity Identity) error
	Find(ctx context.Context, id ID) (User, error)
	FindByLogin(ctx context.Context, login Login) (User, error)
}

// Service creates accounts.
type Service struct {
	repo Repository
	now  func() time.Time
}

// NewService returns a service that reads the clock from time.Now.
func NewService(repo Repository) *Service {
	return &Service{repo: repo, now: time.Now}
}

// Create stores a user and a password identity.
// The password is hashed before the write. Only the hash is stored.
func (s *Service) Create(ctx context.Context, login Login, password Password) (User, error) {
	if login.value == "" {
		return User{}, ErrInvalidLogin
	}
	if password.raw == "" {
		return User{}, ErrEmptyPassword
	}
	id := NewID()
	identityID := NewIdentityID()
	hash, err := HashPassword(password)
	if err != nil {
		return User{}, err
	}
	now := s.now().UTC()
	account := User{ID: id, Login: login, CreatedAt: now}
	identity := Identity{
		ID:        identityID,
		UserID:    id,
		Kind:      KindPassword,
		Secret:    hash,
		CreatedAt: now,
	}
	if err := s.repo.Create(ctx, account, identity); err != nil {
		return User{}, err
	}
	return account, nil
}

// Find returns ErrNotFound when no user has this id.
func (s *Service) Find(ctx context.Context, id ID) (User, error) {
	if s == nil || s.repo == nil {
		return User{}, errors.New("users: repository is missing")
	}
	if id == (ID{}) {
		return User{}, ErrNotFound
	}
	return s.repo.Find(ctx, id)
}

// FindByLogin returns ErrNotFound when no user has this login.
// A disabled user is returned.
func (s *Service) FindByLogin(ctx context.Context, login Login) (User, error) {
	if s == nil || s.repo == nil {
		return User{}, errors.New("users: repository is missing")
	}
	if login.value == "" {
		return User{}, ErrInvalidLogin
	}
	return s.repo.FindByLogin(ctx, login)
}

// String returns the stored kind.
func (k Kind) String() string {
	return string(k)
}
