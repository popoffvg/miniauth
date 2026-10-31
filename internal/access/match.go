package access

// Match returns the resource whose prefix is the longest one that covers the URL path.
// Only a resource on the same host can match.
func Match(resources []Resource, target RequestURL) (Resource, bool) {
	var best Resource
	found := false
	for _, resource := range resources {
		if resource.URL.Host != target.Host() || !resource.URL.Prefix.Covers(target.Path()) {
			continue
		}
		if !found || len(resource.URL.Prefix.String()) > len(best.URL.Prefix.String()) {
			best = resource
			found = true
		}
	}
	return best, found
}
