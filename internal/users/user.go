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
)

// User is an account. It is comparable.
type User struct {
	ID        ID
	Login     Login
	CreatedAt time.Time
}

// Identity is one proof of a user. Secret is the argon2id PHC string for KindPassword.
type Identity struct {
	ID        IdentityID
	UserID    ID
	Kind      Kind
	Secret    PasswordHash
	CreatedAt time.Time
}

// Repository stores users and their identities.
// Create inserts the user and the identity together.
// Create MUST return ErrLoginTaken when the login is already stored.
// Create MUST NOT write the password. It writes the PHC string.
// Find MUST return ErrNotFound when the id is not stored.
type Repository interface {
	Create(ctx context.Context, account User, identity Identity) error
	Find(ctx context.Context, id ID) (User, error)
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

// String returns the stored kind.
func (k Kind) String() string {
	return string(k)
}
