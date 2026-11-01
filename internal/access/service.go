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
// CreateGrant MUST return ErrResourceNotFound, ErrUnknownUser, ErrUnknownGroup, or ErrDuplicateGrant for those cases.
// DeleteGrant and FindGrant MUST return ErrGrantNotFound for a missing id.
// ListResources returns the resources on one host. ListGrants returns every grant of one resource, expired ones too.
// ListGrantEntries returns the grants that match the filter, expired ones too, in resource name order.
type Repository interface {
	CreateResource(ctx context.Context, resource Resource) error
	DeleteResource(ctx context.Context, name ResourceName) error
	FindResource(ctx context.Context, name ResourceName) (Resource, error)
	ListResources(ctx context.Context, host Host) ([]Resource, error)
	ListAllResources(ctx context.Context) ([]Resource, error)
	CreateGrant(ctx context.Context, grant Grant) error
	DeleteGrant(ctx context.Context, id GrantID) error
	FindGrant(ctx context.Context, id GrantID) (Grant, error)
	ListGrants(ctx context.Context, resource ResourceName) ([]Grant, error)
	ListGrantEntries(ctx context.Context, filter GrantFilter) ([]GrantEntry, error)
}

// UserDirectory finds a user by login. FindByLogin MUST return users.ErrNotFound when no user matches.
type UserDirectory interface {
	FindByLogin(ctx context.Context, login users.Login) (users.User, error)
}

// Service checks URLs against grants and changes resources and grants.
// It keeps no cache, so a revoke applies to the next check.
type Service struct {
	repo     Repository
	accounts UserDirectory
	now      func() time.Time
}

// NewService returns a service that reads the clock from time.Now.
// A nil accounts value is allowed when no caller names a user by login: GrantTo and ListGrants then fail for a user.
func NewService(repo Repository, accounts UserDirectory) *Service {
	return &Service{repo: repo, accounts: accounts, now: time.Now}
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

// DeleteResource deletes the resource and its grants. A managed resource is ErrManagedResource.
func (s *Service) DeleteResource(ctx context.Context, name ResourceName) error {
	if err := s.ready(); err != nil {
		return err
	}
	found, err := s.repo.FindResource(ctx, name)
	if err != nil {
		return err
	}
	if found.Managed {
		return ErrManagedResource
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

// Revoke deletes the grant. The next Check does not count it. A managed grant is ErrManagedGrant.
func (s *Service) Revoke(ctx context.Context, id GrantID) error {
	if err := s.ready(); err != nil {
		return err
	}
	found, err := s.repo.FindGrant(ctx, id)
	if err != nil {
		return err
	}
	if found.Managed {
		return ErrManagedGrant
	}
	return s.repo.DeleteGrant(ctx, id)
}

// ListResources returns every resource in name order.
func (s *Service) ListResources(ctx context.Context) ([]Resource, error) {
	if err := s.ready(); err != nil {
		return nil, err
	}
	return s.repo.ListAllResources(ctx)
}

// MatchResource returns the resource that covers target, with the longest prefix, or ErrNoResource.
// It reads no grant: it names the resource, not who may reach it.
func (s *Service) MatchResource(ctx context.Context, target RequestURL) (Resource, error) {
	if err := s.ready(); err != nil {
		return Resource{}, err
	}
	resources, err := s.repo.ListResources(ctx, target.Host())
	if err != nil {
		return Resource{}, err
	}
	resource, ok := Match(resources, target)
	if !ok {
		return Resource{}, ErrNoResource
	}
	return resource, nil
}

// FindResourceByURL returns the resource whose host and prefix equal url, or ErrResourceNotFound.
func (s *Service) FindResourceByURL(ctx context.Context, url ResourceURL) (Resource, error) {
	if err := s.ready(); err != nil {
		return Resource{}, err
	}
	resources, err := s.repo.ListResources(ctx, url.Host)
	if err != nil {
		return Resource{}, err
	}
	for _, resource := range resources {
		if resource.URL == url {
			return resource, nil
		}
	}
	return Resource{}, ErrResourceNotFound
}

// GrantTo gives the user or the group in grantee the resource. A zero expiry never expires.
// It returns ErrResourceName, ErrSubject, ErrExpiry, ErrUnknownUser, ErrUnknownGroup, ErrResourceNotFound, or ErrDuplicateGrant for those cases.
func (s *Service) GrantTo(ctx context.Context, resource ResourceName, grantee Grantee, expiry Expiry) (GrantEntry, error) {
	if err := s.ready(); err != nil {
		return GrantEntry{}, err
	}
	if resource == (ResourceName{}) {
		return GrantEntry{}, ErrResourceName
	}
	if !grantee.Valid() {
		return GrantEntry{}, ErrSubject
	}
	if !expiry.ActiveAt(s.now()) {
		return GrantEntry{}, ErrExpiry
	}
	subject := GroupSubject(grantee.Group)
	if grantee.User != (users.Login{}) {
		account, err := s.findUser(ctx, grantee.User)
		if err != nil {
			return GrantEntry{}, err
		}
		subject = UserSubject(account.ID)
	}
	found, err := s.repo.FindResource(ctx, resource)
	if err != nil {
		return GrantEntry{}, err
	}
	grant, err := s.Grant(ctx, resource, subject, expiry)
	if err != nil {
		return GrantEntry{}, err
	}
	return GrantEntry{Grant: grant, URL: found.URL, UserLogin: grantee.User}, nil
}

// ListGrants returns the grants that match filter, expired ones too.
// A user or a resource in filter that is not stored is ErrUnknownUser or ErrResourceNotFound.
func (s *Service) ListGrants(ctx context.Context, filter GrantFilter) ([]GrantEntry, error) {
	if err := s.ready(); err != nil {
		return nil, err
	}
	if filter.User != (users.Login{}) {
		if _, err := s.findUser(ctx, filter.User); err != nil {
			return nil, err
		}
	}
	if filter.Resource != (ResourceName{}) {
		if _, err := s.repo.FindResource(ctx, filter.Resource); err != nil {
			return nil, err
		}
	}
	return s.repo.ListGrantEntries(ctx, filter)
}

// findUser returns ErrUnknownUser for a login that no user has.
func (s *Service) findUser(ctx context.Context, login users.Login) (users.User, error) {
	if s.accounts == nil {
		return users.User{}, errors.New("access: user directory is missing")
	}
	account, err := s.accounts.FindByLogin(ctx, login)
	if errors.Is(err, users.ErrNotFound) {
		return users.User{}, ErrUnknownUser
	}
	return account, err
}

func (s *Service) ready() error {
	if s == nil || s.repo == nil {
		return errors.New("access: repository is missing")
	}
	return nil
}
