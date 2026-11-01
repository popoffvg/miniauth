package access

// Resource is a named URL prefix that /auth/check protects.
// A Managed resource comes from the resources file: only the reconciler changes it.
type Resource struct {
	Name    ResourceName
	URL     ResourceURL
	Managed bool
}
