// Package accesstest is an in-memory access.Repository for tests.
package accesstest

import (
	"context"
	"slices"
	"strings"
	"sync"

	"github.com/popoffvg/miniauth/internal/access"
	"github.com/popoffvg/miniauth/internal/users"
)

// Repository keeps resources and grants in memory. It is safe for concurrent use.
// CreateGrant never returns access.ErrUnknownUser.
type Repository struct {
	mu        sync.Mutex
	resources []access.Resource
	grants    []access.Grant
	logins    map[users.ID]users.Login
}

// AddUser stores the login that ListGrantEntries shows for a user grant.
func (r *Repository) AddUser(id users.ID, login users.Login) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.logins == nil {
		r.logins = map[users.ID]users.Login{}
	}
	r.logins[id] = login
}

// ListAllResources returns every resource in name order.
func (r *Repository) ListAllResources(_ context.Context) ([]access.Resource, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	found := slices.Clone(r.resources)
	slices.SortFunc(found, func(a, b access.Resource) int { return strings.Compare(a.Name.String(), b.Name.String()) })
	return found, nil
}

// ListGrantEntries returns the grants that match filter, in resource name order and then in the order they were stored.
func (r *Repository) ListGrantEntries(_ context.Context, filter access.GrantFilter) ([]access.GrantEntry, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var found []access.GrantEntry
	for _, grant := range r.grants {
		var login users.Login
		if id, ok := grant.Subject.User(); ok {
			login = r.logins[id]
		}
		if filter.User != (users.Login{}) && filter.User != login {
			continue
		}
		if filter.Resource != (access.ResourceName{}) && filter.Resource != grant.Resource {
			continue
		}
		index := slices.IndexFunc(r.resources, func(stored access.Resource) bool { return stored.Name == grant.Resource })
		found = append(found, access.GrantEntry{Grant: grant, URL: r.resources[index].URL, UserLogin: login})
	}
	slices.SortStableFunc(found, func(a, b access.GrantEntry) int {
		return strings.Compare(a.Grant.Resource.String(), b.Grant.Resource.String())
	})
	return found, nil
}

// NewRepository returns an empty repository.
func NewRepository() *Repository {
	return &Repository{}
}

var _ access.Repository = (*Repository)(nil)

// CreateResource stores the resource.
func (r *Repository) CreateResource(_ context.Context, resource access.Resource) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, stored := range r.resources {
		if stored.Name == resource.Name || stored.URL == resource.URL {
			return access.ErrDuplicateResource
		}
	}
	r.resources = append(r.resources, resource)
	return nil
}

// DeleteResource deletes the resource and its grants.
func (r *Repository) DeleteResource(_ context.Context, name access.ResourceName) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	before := len(r.resources)
	r.resources = slices.DeleteFunc(r.resources, func(stored access.Resource) bool { return stored.Name == name })
	if len(r.resources) == before {
		return access.ErrResourceNotFound
	}
	r.grants = slices.DeleteFunc(r.grants, func(grant access.Grant) bool { return grant.Resource == name })
	return nil
}

// FindResource returns the resource with the name.
func (r *Repository) FindResource(_ context.Context, name access.ResourceName) (access.Resource, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, stored := range r.resources {
		if stored.Name == name {
			return stored, nil
		}
	}
	return access.Resource{}, access.ErrResourceNotFound
}

// ListResources returns the resources on host.
func (r *Repository) ListResources(_ context.Context, host access.Host) ([]access.Resource, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var found []access.Resource
	for _, stored := range r.resources {
		if stored.URL.Host == host {
			found = append(found, stored)
		}
	}
	return found, nil
}

// CreateGrant stores the grant. The expiry is not checked, so a test can store an expired grant.
func (r *Repository) CreateGrant(_ context.Context, grant access.Grant) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !slices.ContainsFunc(r.resources, func(stored access.Resource) bool { return stored.Name == grant.Resource }) {
		return access.ErrResourceNotFound
	}
	for _, stored := range r.grants {
		if stored.Resource == grant.Resource && stored.Subject == grant.Subject {
			return access.ErrDuplicateGrant
		}
	}
	r.grants = append(r.grants, grant)
	return nil
}

// DeleteGrant deletes the grant.
func (r *Repository) DeleteGrant(_ context.Context, id access.GrantID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	before := len(r.grants)
	r.grants = slices.DeleteFunc(r.grants, func(grant access.Grant) bool { return grant.ID == id })
	if len(r.grants) == before {
		return access.ErrGrantNotFound
	}
	return nil
}

// ListGrants returns the grants of the resource.
func (r *Repository) ListGrants(_ context.Context, resource access.ResourceName) ([]access.Grant, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var found []access.Grant
	for _, grant := range r.grants {
		if grant.Resource == resource {
			found = append(found, grant)
		}
	}
	return found, nil
}
