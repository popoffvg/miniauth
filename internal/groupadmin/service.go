package groupadmin

import (
	"context"
	"errors"
	"time"

	"github.com/popoffvg/miniauth/internal/access"
	"github.com/popoffvg/miniauth/internal/groups"
)

// Store keeps the groups.
// ListGroups returns every group in name order.
// FindGroup and DeleteGroup MUST return groups.ErrGroupNotFound for a name that is not stored.
// CreateGroup MUST return groups.ErrDuplicateGroup for a name that is stored.
// DeleteGroup also deletes the memberships and the grants of the group. It MUST NOT delete a built-in group.
type Store interface {
	ListGroups(ctx context.Context) ([]Group, error)
	FindGroup(ctx context.Context, name groups.Name) (Group, error)
	CreateGroup(ctx context.Context, name groups.Name, at time.Time) error
	DeleteGroup(ctx context.Context, name groups.Name) error
}

// grantService is the one path that changes grants. *access.Service fits.
type grantService interface {
	GrantTo(ctx context.Context, resource access.ResourceName, grantee access.Grantee, expiry access.Expiry) (access.GrantEntry, error)
	ListGrants(ctx context.Context, filter access.GrantFilter) ([]access.GrantEntry, error)
	Revoke(ctx context.Context, id access.GrantID) error
}

// Service changes groups and the resources of a group.
type Service struct {
	store  Store
	grants grantService
	now    func() time.Time
}

// NewService reads the clock from time.Now.
func NewService(store Store, grants grantService) (*Service, error) {
	if store == nil || grants == nil {
		return nil, errors.New("groupadmin: store or grant service is missing")
	}
	return &Service{store: store, grants: grants, now: time.Now}, nil
}

// List returns every group with its member count and its resources.
func (s *Service) List(ctx context.Context) ([]Group, error) {
	return s.store.ListGroups(ctx)
}

// Create stores an empty group. A stored name is groups.ErrDuplicateGroup.
func (s *Service) Create(ctx context.Context, name groups.Name) (Group, error) {
	if name == (groups.Name{}) {
		return Group{}, groups.ErrName
	}
	group := Group{Name: name, CreatedAt: s.now().UTC()}
	if err := s.store.CreateGroup(ctx, name, group.CreatedAt); err != nil {
		return Group{}, err
	}
	return group, nil
}

// Delete deletes the group, its memberships, and its grants.
// A built-in group is groups.ErrBuiltIn. A group that the resources file names is ErrManagedGroup:
// the next start would create it again.
func (s *Service) Delete(ctx context.Context, name groups.Name) error {
	if name.BuiltIn() {
		return groups.ErrBuiltIn
	}
	group, err := s.store.FindGroup(ctx, name)
	if err != nil {
		return err
	}
	if group.Managed() {
		return ErrManagedGroup
	}
	return s.store.DeleteGroup(ctx, name)
}

// AddResource grants the resource to the group with no expiry. A group that has an active grant keeps it.
// An expired grant is replaced by a grant with no expiry.
func (s *Service) AddResource(ctx context.Context, name groups.Name, resource access.ResourceName) error {
	if _, err := s.store.FindGroup(ctx, name); err != nil {
		return err
	}
	_, err := s.grants.GrantTo(ctx, resource, access.Grantee{Group: name}, access.Expiry{})
	if !errors.Is(err, access.ErrDuplicateGrant) {
		return err
	}
	entry, err := s.groupGrant(ctx, name, resource)
	if err != nil || entry.Grant.Expiry.ActiveAt(s.now()) {
		return err
	}
	if err = s.grants.Revoke(ctx, entry.Grant.ID); err != nil {
		return err
	}
	_, err = s.grants.GrantTo(ctx, resource, access.Grantee{Group: name}, access.Expiry{})
	return err
}

// groupGrant returns the grant of the resource to the group, or ErrNotGranted.
func (s *Service) groupGrant(ctx context.Context, name groups.Name, resource access.ResourceName) (access.GrantEntry, error) {
	entries, err := s.grants.ListGrants(ctx, access.GrantFilter{Resource: resource})
	if err != nil {
		return access.GrantEntry{}, err
	}
	for _, entry := range entries {
		if group, ok := entry.Grant.Subject.Group(); ok && group == name {
			return entry, nil
		}
	}
	return access.GrantEntry{}, ErrNotGranted
}

// RemoveResource revokes the grant of the resource to the group.
// A grant from the resources file is access.ErrManagedGrant.
func (s *Service) RemoveResource(ctx context.Context, name groups.Name, resource access.ResourceName) error {
	if _, err := s.store.FindGroup(ctx, name); err != nil {
		return err
	}
	entry, err := s.groupGrant(ctx, name, resource)
	if err != nil {
		return err
	}
	return s.grants.Revoke(ctx, entry.Grant.ID)
}
