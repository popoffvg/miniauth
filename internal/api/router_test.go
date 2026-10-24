package api

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"
)

func TestHealthz(t *testing.T) {
	router := NewRouter(nil, AdminTokenHash{}, nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("GET /healthz: got %d, want %d", rec.Code, http.StatusNoContent)
	}
}

func TestHealthzRejectsPost(t *testing.T) {
	router := NewRouter(nil, AdminTokenHash{}, nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/healthz", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST /healthz: got %d, want %d", rec.Code, http.StatusMethodNotAllowed)
	}
}

func TestRouterRoutesMatchOpenAPI(t *testing.T) {
	router := NewRouter(nil, AdminTokenHash{}, nil)
	got := muxRoutes(t, router.mux)
	if len(got) == 0 {
		t.Fatal("no routes found on the mux")
	}
	want := openAPIRoutes(t, openAPIPath(t))
	missing, extra := compareRoutes(got, want)
	for _, route := range missing {
		t.Errorf("router route %s %s is not in api/openapi.yaml", route.method, route.path)
	}
	for _, route := range extra {
		t.Errorf("api/openapi.yaml describes %s %s but the router does not", route.method, route.path)
	}
}

func TestCompareRoutesReportsARouterRouteMissingFromTheSpec(t *testing.T) {
	got := []route{{method: http.MethodGet, path: "/healthz"}, {method: http.MethodPost, path: "/api/v1/users"}}
	want := []route{{method: http.MethodGet, path: "/healthz"}}
	missing, extra := compareRoutes(got, want)
	if len(missing) != 1 || missing[0].path != "/api/v1/users" {
		t.Fatalf("missing = %+v", missing)
	}
	if len(extra) != 0 {
		t.Fatalf("extra = %+v", extra)
	}
}

type route struct {
	method string
	path   string
}

func compareRoutes(routerRoutes, specRoutes []route) (missing, extra []route) {
	spec := map[route]struct{}{}
	for _, route := range specRoutes {
		spec[route] = struct{}{}
	}
	seen := map[route]struct{}{}
	for _, route := range routerRoutes {
		seen[route] = struct{}{}
		if _, ok := spec[route]; !ok {
			missing = append(missing, route)
		}
	}
	for _, route := range specRoutes {
		if _, ok := seen[route]; !ok {
			extra = append(extra, route)
		}
	}
	slices.SortFunc(missing, routeLess)
	slices.SortFunc(extra, routeLess)
	return missing, extra
}

func routeLess(a, b route) int {
	if a.method != b.method {
		return strings.Compare(a.method, b.method)
	}
	return strings.Compare(a.path, b.path)
}

func openAPIPath(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("test file path is unknown")
	}
	return filepath.Join(filepath.Dir(file), "..", "..", "api", "openapi.yaml")
}

func openAPIRoutes(t *testing.T, path string) []route {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	routes, err := parseOpenAPIRoutes(body)
	if err != nil {
		t.Fatal(err)
	}
	return routes
}

// parseOpenAPIRoutes reads path keys and HTTP methods from an OpenAPI YAML document.
// The document uses block style. Paths sit under the root key "paths".
func parseOpenAPIRoutes(body []byte) ([]route, error) {
	methods := map[string]string{
		"get":     http.MethodGet,
		"head":    http.MethodHead,
		"post":    http.MethodPost,
		"put":     http.MethodPut,
		"patch":   http.MethodPatch,
		"delete":  http.MethodDelete,
		"options": http.MethodOptions,
		"trace":   http.MethodTrace,
	}
	var routes []route
	inPaths := false
	pathsIndent := 0
	pathIndent := -1
	currentPath := ""
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimRight(line, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.Contains(line, "\t") {
			return nil, errors.New("api: openapi uses tabs")
		}
		indent := len(line) - len(strings.TrimLeft(line, " "))
		key, _, _ := strings.Cut(trimmed, ":")
		key = strings.Trim(strings.TrimSpace(key), `"'`)
		if !inPaths {
			if indent == 0 && key == "paths" {
				inPaths = true
				pathsIndent = indent
			}
			continue
		}
		if indent <= pathsIndent {
			break
		}
		if pathIndent < 0 {
			pathIndent = indent
		}
		if indent == pathIndent {
			if !strings.HasPrefix(key, "/") {
				return nil, fmt.Errorf("api: openapi path %q", key)
			}
			currentPath = key
			continue
		}
		if currentPath != "" && indent == pathIndent+2 {
			if method, ok := methods[strings.ToLower(key)]; ok {
				routes = append(routes, route{method: method, path: currentPath})
			}
		}
	}
	if !inPaths {
		return nil, errors.New("api: openapi has no paths")
	}
	return routes, nil
}

// muxRoutes reads the patterns registered on mux.
// net/http.ServeMux does not export them.
// The walk follows the unexported routing tree of Go 1.27.
func muxRoutes(t *testing.T, mux *http.ServeMux) []route {
	t.Helper()
	root := reflect.ValueOf(mux).Elem().FieldByName("tree")
	var patterns []string
	var walk func(reflect.Value)
	walk = func(node reflect.Value) {
		if !node.IsValid() {
			return
		}
		if node.Kind() == reflect.Pointer {
			if node.IsNil() {
				return
			}
			node = node.Elem()
		}
		pattern := node.FieldByName("pattern")
		if pattern.IsValid() && pattern.Kind() == reflect.Pointer && !pattern.IsNil() {
			patterns = append(patterns, pattern.Elem().FieldByName("str").String())
		}
		if child := node.FieldByName("multiChild"); child.IsValid() {
			walk(child)
		}
		if child := node.FieldByName("emptyChild"); child.IsValid() {
			walk(child)
		}
		children := node.FieldByName("children")
		if !children.IsValid() {
			return
		}
		pairs := children.FieldByName("s")
		for i := 0; i < pairs.Len(); i++ {
			walk(pairs.Index(i).FieldByName("value"))
		}
		index := children.FieldByName("m")
		if index.Kind() == reflect.Map && !index.IsNil() {
			iter := index.MapRange()
			for iter.Next() {
				walk(iter.Value())
			}
		}
	}
	walk(root)

	var routes []route
	for _, pattern := range patterns {
		method, path, ok := strings.Cut(pattern, " ")
		if !ok || !strings.HasPrefix(path, "/") {
			t.Fatalf("pattern %q is not a method and a path", pattern)
		}
		routes = append(routes, route{method: method, path: path})
	}
	return routes
}
