// Package access decides which user may reach which URL.
// A resource is a host and a path prefix. A grant gives one user or one group one resource.
// A URL that matches no resource is denied. A URL with no active grant is denied.
package access
