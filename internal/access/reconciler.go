package access

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/popoffvg/miniauth/internal/groups"
)

// ManagedStore runs the writes of one reconcile in one transaction. An error from fn rolls back every write of fn.
type ManagedStore interface {
	InTransaction(ctx context.Context, fn func(ManagedWriter) error) error
}

// GroupGrantKey names one group grant: a resource and a group.
type GroupGrantKey struct {
	Resource ResourceName
	Group    groups.Name
}

// ManagedWriter writes the managed rows. No method changes a row that is not managed, except:
// PutManagedResource and PutManagedGrant mark a stored row with the same key as managed.
// PutManagedResource MUST return ErrDuplicateResource when an unmanaged resource has the URL.
// Two managed resources MAY swap their URLs in one transaction.
// DeleteStaleGrants deletes every managed grant whose key is not in keep.
// DeleteStaleResources deletes every managed resource whose name is not in keep, with all its grants.
type ManagedWriter interface {
	DeleteStaleGrants(ctx context.Context, keep []GroupGrantKey) error
	DeleteStaleResources(ctx context.Context, keep []ResourceName) error
	EnsureGroup(ctx context.Context, name groups.Name, at time.Time) error
	PutManagedResource(ctx context.Context, resource Resource) error
	PutManagedGrant(ctx context.Context, grant Grant) error
}

// Reconciler makes the managed rows equal to the resources file.
type Reconciler struct {
	store ManagedStore
	now   func() time.Time
}

// NewReconciler reads the clock from time.Now.
func NewReconciler(store ManagedStore) (*Reconciler, error) {
	if store == nil {
		return nil, errors.New("access: managed store is missing")
	}
	return &Reconciler{store: store, now: time.Now}, nil
}

// Reconcile creates or updates each entry and its group grants, creates each missing group,
// and deletes the managed rows that no entry names. An empty list deletes every managed row.
// An error names the index of the entry.
func (r *Reconciler) Reconcile(ctx context.Context, entries []PredefinedResource) error {
	now := r.now().UTC()
	keepResources := make([]ResourceName, 0, len(entries))
	var keepGrants []GroupGrantKey
	for _, entry := range entries {
		keepResources = append(keepResources, entry.Name)
		for _, name := range entry.Groups {
			keepGrants = append(keepGrants, GroupGrantKey{Resource: entry.Name, Group: name})
		}
	}
	return r.store.InTransaction(ctx, func(tx ManagedWriter) error {
		if err := tx.DeleteStaleGrants(ctx, keepGrants); err != nil {
			return err
		}
		if err := tx.DeleteStaleResources(ctx, keepResources); err != nil {
			return err
		}
		for i, entry := range entries {
			if err := putEntry(ctx, tx, entry, now); err != nil {
				return fmt.Errorf("access: predefined resource %d: %w", i, err)
			}
		}
		return nil
	})
}

func putEntry(ctx context.Context, tx ManagedWriter, entry PredefinedResource, now time.Time) error {
	if err := tx.PutManagedResource(ctx, Resource{Name: entry.Name, URL: entry.URL, Managed: true}); err != nil {
		return err
	}
	for _, name := range entry.Groups {
		if err := tx.EnsureGroup(ctx, name, now); err != nil {
			return err
		}
		grant := Grant{ID: NewGrantID(), Resource: entry.Name, Subject: GroupSubject(name), CreatedAt: now, Managed: true}
		if err := tx.PutManagedGrant(ctx, grant); err != nil {
			return err
		}
	}
	return nil
}
