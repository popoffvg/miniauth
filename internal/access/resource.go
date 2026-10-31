package access

// Resource is a named URL prefix that /auth/check protects.
type Resource struct {
	Name ResourceName
	URL  ResourceURL
}
