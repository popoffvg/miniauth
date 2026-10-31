package access

import (
	"context"
	"errors"
	"time"

	"github.com/popoffvg/miniauth/internal/groups"
	"github.com/popoffvg/miniauth/internal/users"
)

// Repository stores resources and grants.
// CreateResource MUST return ErrDuplicateResource when the name or the URL is stored.
// DeleteResource and FindResource MUST return ErrResourceNotFound for a missing name.
// DeleteResource also deletes the grants of the resource.
// CreateGrant MUST return ErrResourceNotFound, ErrUnknownUser, or ErrDuplicateGrant for those cases.
// DeleteGrant MUST return ErrGrantNotFound for a missing id.
// ListResources returns the resources on one host. ListGrants returns every grant of one resource, expired ones too.
type Repository interface {
	CreateResource(ctx context.Context, resource Resource) error
	DeleteResource(ctx context.Context, name ResourceName) error
	FindResource(ctx context.Context, name ResourceName) (Resource, error)
	ListResources(ctx context.Context, host Host) ([]Resource, error)
	CreateGrant(ctx context.Context, grant Grant) error
	DeleteGrant(ctx context.Context, id GrantID) error
	ListGrants(ctx context.Context, resource ResourceName) ([]Grant, error)
}

// Service checks URLs against grants and changes resources and grants.
// It keeps no cache, so a revoke applies to the next check.
type Service struct {
	repo Repository
	now  func() time.Time
}

// NewService returns a service that reads the clock from time.Now.
func NewService(repo Repository) *Service {
	return &Service{repo: repo, now: time.Now}
}

// Check returns nil when the user or one of userGroups has an active grant
// for the resource that matches target.
// It returns ErrNoResource when no resource matches and ErrNoGrant when no grant counts.
func (s *Service) Check(ctx context.Context, user users.ID, userGroups []groups.Name, target RequestURL) error {
	if err := s.ready(); err != nil {
		return err
	}
	resources, err := s.repo.ListResources(ctx, target.Host())
	if err != nil {
		return err
	}
	resource, ok := Match(resources, target)
	if !ok {
		return ErrNoResource
	}
	grants, err := s.repo.ListGrants(ctx, resource.Name)
	if err != nil {
		return err
	}
	now := s.now()
	for _, grant := range grants {
		if grant.Expiry.ActiveAt(now) && grant.Subject.Covers(user, userGroups) {
			return nil
		}
	}
	return ErrNoGrant
}

// CreateResource stores a resource with a unique name and a unique URL.
func (s *Service) CreateResource(ctx context.Context, name ResourceName, url ResourceURL) (Resource, error) {
	if err := s.ready(); err != nil {
		return Resource{}, err
	}
	if name == (ResourceName{}) {
		return Resource{}, ErrResourceName
	}
	if url.Host == (Host{}) {
		return Resource{}, ErrHost
	}
	if url.Prefix == (PathPrefix{}) {
		return Resource{}, ErrPathPrefix
	}
	resource := Resource{Name: name, URL: url}
	if err := s.repo.CreateResource(ctx, resource); err != nil {
		return Resource{}, err
	}
	return resource, nil
}

// DeleteResource deletes the resource and its grants.
func (s *Service) DeleteResource(ctx context.Context, name ResourceName) error {
	if err := s.ready(); err != nil {
		return err
	}
	return s.repo.DeleteResource(ctx, name)
}

// Grant gives subject the resource. A zero expiry never expires.
// An expiry at or before now is refused with ErrExpiry.
func (s *Service) Grant(ctx context.Context, resource ResourceName, subject Subject, expiry Expiry) (Grant, error) {
	if err := s.ready(); err != nil {
		return Grant{}, err
	}
	if !subject.Valid() {
		return Grant{}, ErrSubject
	}
	now := s.now().UTC()
	if !expiry.ActiveAt(now) {
		return Grant{}, ErrExpiry
	}
	grant := Grant{
		ID:        NewGrantID(),
		Resource:  resource,
		Subject:   subject,
		Expiry:    expiry,
		CreatedAt: now,
	}
	if err := s.repo.CreateGrant(ctx, grant); err != nil {
		return Grant{}, err
	}
	return grant, nil
}

// Revoke deletes the grant. The next Check does not count it.
func (s *Service) Revoke(ctx context.Context, id GrantID) error {
	if err := s.ready(); err != nil {
		return err
	}
	return s.repo.DeleteGrant(ctx, id)
}

// ListGrants returns every grant of the resource, expired ones too.
func (s *Service) ListGrants(ctx context.Context, resource ResourceName) ([]Grant, error) {
	if err := s.ready(); err != nil {
		return nil, err
	}
	if _, err := s.repo.FindResource(ctx, resource); err != nil {
		return nil, err
	}
	return s.repo.ListGrants(ctx, resource)
}

func (s *Service) ready() error {
	if s == nil || s.repo == nil {
		return errors.New("access: repository is missing")
	}
	return nil
}
