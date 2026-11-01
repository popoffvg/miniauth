package api

import (
	"errors"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/popoffvg/miniauth/internal/groups"
	"github.com/popoffvg/miniauth/internal/sessions"
	"github.com/popoffvg/miniauth/internal/users"
)

const (
	headerAuthUser   = "X-Auth-User"
	headerAuthEmail  = "X-Auth-Email"
	headerAuthGroups = "X-Auth-Groups"
	headerAuthMethod = "X-Auth-Method"
)

// forwardAuthRequest documents the query Traefik sends.
// scope is not a limit. A token limits itself with its own scopes.
type forwardAuthRequest struct {
	Scope string `query:"scope"`
	Group string `query:"group"`
}

func (s *service) forwardAuth(w http.ResponseWriter, r *http.Request) {
	need, ok := requiredGroups(r)
	if !ok {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	if bearer, ok := accessTokenBearer(r); ok {
		s.forwardAuthToken(w, r, need, bearer)
		return
	}
	session, err := s.openBrowserSession(w, r)
	if errors.Is(err, sessions.ErrNotFound) {
		s.unauthenticated(w, r)
		return
	}
	if err != nil {
		loggerFrom(r.Context()).ErrorContext(r.Context(), "miniauth: auth check", "err", err)
		writeProblem(w, http.StatusInternalServerError, "The check failed.")
		return
	}
	user, err := s.accounts.Find(r.Context(), session.UserID)
	if errors.Is(err, users.ErrNotFound) || err == nil && user.Disabled() {
		s.unauthenticated(w, r)
		return
	}
	if err != nil {
		loggerFrom(r.Context()).ErrorContext(r.Context(), "miniauth: auth check", "err", err)
		writeProblem(w, http.StatusInternalServerError, "The check failed.")
		return
	}
	have, err := s.groups.List(r.Context(), user.ID)
	if err != nil {
		loggerFrom(r.Context()).ErrorContext(r.Context(), "miniauth: auth check", "err", err)
		writeProblem(w, http.StatusInternalServerError, "The check failed.")
		return
	}
	if !hasGroups(have, need) {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	if !s.urlGranted(w, r, user, have) {
		return
	}
	method := sessions.MethodFromFactors(session.Factors)
	if !writeAuthHeaders(w, user.Login, have, method) {
		loggerFrom(r.Context()).ErrorContext(r.Context(), "miniauth: auth check", "err", errors.New("api: auth header is not safe"))
		writeProblem(w, http.StatusInternalServerError, "The check failed.")
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *service) unauthenticated(w http.ResponseWriter, r *http.Request) {
	if sessionCookiePresent(r) {
		sessions.ClearCookie(w, s.domain)
	}
	if browserRequest(r) {
		w.Header().Set("Location", s.publicURL.Login(returnURL(r, s.domain, s.publicURL)))
		w.WriteHeader(http.StatusFound)
		return
	}
	w.Header().Set("WWW-Authenticate", s.bearerChallenge(r, false))
	w.WriteHeader(http.StatusUnauthorized)
}

func requiredGroups(r *http.Request) ([]groups.Name, bool) {
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return nil, false
	}
	rawNames, ok := query["group"]
	if !ok {
		return nil, true
	}
	need := make([]groups.Name, 0, len(rawNames))
	for _, raw := range rawNames {
		name, err := groups.ParseName(raw)
		if err != nil {
			return nil, false
		}
		need = append(need, name)
	}
	return need, true
}

func hasGroups(have, need []groups.Name) bool {
	if len(need) == 0 {
		return true
	}
	set := make(map[groups.Name]struct{}, len(have))
	for _, name := range have {
		set[name] = struct{}{}
	}
	for _, name := range need {
		if _, ok := set[name]; !ok {
			return false
		}
	}
	return true
}

func writeAuthHeaders(w http.ResponseWriter, login users.Login, names []groups.Name, method sessions.Method) bool {
	userName := login.String()
	email := emailFromLogin(login)
	groupsHeader := joinGroups(names)
	methodHeader := method.String()
	if !safeHeader(userName) || !safeHeader(email) || !safeHeader(groupsHeader) || !safeHeader(methodHeader) {
		return false
	}
	w.Header().Set(headerAuthUser, userName)
	w.Header().Set(headerAuthEmail, email)
	w.Header().Set(headerAuthGroups, groupsHeader)
	w.Header().Set(headerAuthMethod, methodHeader)
	return true
}

func emailFromLogin(login users.Login) string {
	if email, ok := login.Email(); ok {
		return email.String()
	}
	return ""
}

func joinGroups(names []groups.Name) string {
	parts := make([]string, len(names))
	for i, name := range names {
		parts[i] = name.String()
	}
	slices.Sort(parts)
	return strings.Join(parts, ",")
}

func safeHeader(value string) bool {
	if strings.ContainsAny(value, "\r\n") {
		return false
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

// browserRequest reports a navigation the login page can answer.
// A bearer client, an XHR, and a CORS fetch are not navigations.
func browserRequest(r *http.Request) bool {
	if r.Header.Get("Authorization") != "" {
		return false
	}
	if strings.EqualFold(r.Header.Get("X-Requested-With"), "XMLHttpRequest") {
		return false
	}
	switch strings.ToLower(r.Header.Get("Sec-Fetch-Mode")) {
	case "navigate":
		return true
	case "cors", "no-cors", "websocket":
		return false
	}
	if strings.EqualFold(r.Header.Get("Sec-Fetch-Dest"), "document") {
		return true
	}
	return acceptsHTML(r.Header.Get("Accept"))
}

func acceptsHTML(accept string) bool {
	for part := range strings.SplitSeq(accept, ",") {
		media, params, _ := strings.Cut(part, ";")
		if !strings.EqualFold(strings.TrimSpace(media), "text/html") {
			continue
		}
		if mediaQuality(params) > 0 {
			return true
		}
	}
	return false
}

func mediaQuality(params string) float64 {
	quality := 1.0
	for params != "" {
		var param string
		param, params, _ = strings.Cut(params, ";")
		name, value, ok := strings.Cut(param, "=")
		if !ok || !strings.EqualFold(strings.TrimSpace(name), "q") {
			continue
		}
		parsed, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
		if err != nil || parsed < 0 || parsed > 1 {
			return 0
		}
		quality = parsed
	}
	return quality
}

// openBrowserSession opens the first valid session cookie of r.
// When Open moves the expiry, the cookie is set again, so the browser keeps it as long as the database.
func (s *service) openBrowserSession(w http.ResponseWriter, r *http.Request) (sessions.Session, error) {
	var failure error
	for _, id := range sessions.IDsFromRequest(r) {
		session, extended, err := s.browser.Open(r.Context(), id)
		if err == nil {
			if extended {
				sessions.SetCookie(w, id, s.domain, time.Now())
			}
			return session, nil
		}
		if errors.Is(err, sessions.ErrNotFound) {
			continue
		}
		if failure == nil {
			failure = err
		}
	}
	if failure != nil {
		return sessions.Session{}, failure
	}
	return sessions.Session{}, sessions.ErrNotFound
}

func sessionCookiePresent(r *http.Request) bool {
	_, err := r.Cookie(sessions.CookieName)
	return err == nil
}

// returnURL is the page the browser asked for.
// The host must sit under the cookie domain.
// The host must match the public origin when the cookie domain is empty.
// Anything else is empty, so the login page gets no return query.
func returnURL(r *http.Request, domain sessions.Domain, publicURL PublicURL) string {
	forwarded, ok := forwardedURL(r, domain, publicURL)
	if !ok {
		return ""
	}
	return forwarded.String()
}

// forwardedRequest is the URL in X-Forwarded-Proto, X-Forwarded-Host, and X-Forwarded-Uri.
// uri is empty when X-Forwarded-Uri is missing.
type forwardedRequest struct {
	proto string
	host  string
	uri   string
}

// String reads a missing URI as "/".
func (f forwardedRequest) String() string {
	uri := f.uri
	if uri == "" {
		uri = "/"
	}
	return f.proto + "://" + f.host + uri
}

// forwardedURL is the one parser of the forwarded URL.
// ok is false when the scheme, the host, or a present URI is refused.
// The host must sit under the cookie domain, or match the public origin when the domain is empty.
func forwardedURL(r *http.Request, domain sessions.Domain, publicURL PublicURL) (forwardedRequest, bool) {
	proto := strings.ToLower(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")))
	if proto != "http" && proto != "https" {
		return forwardedRequest{}, false
	}
	host := strings.TrimSpace(r.Header.Get("X-Forwarded-Host"))
	if !forwardedHostAllowed(proto, host, domain, publicURL) {
		return forwardedRequest{}, false
	}
	uri := r.Header.Get("X-Forwarded-Uri")
	if uri != "" && !safeForwardedURI(uri) {
		return forwardedRequest{}, false
	}
	return forwardedRequest{proto: proto, host: host, uri: uri}, true
}

// forwardedHostAllowed compares a host with no cookie domain to the public host without the default port of each scheme.
func forwardedHostAllowed(scheme, host string, domain sessions.Domain, publicURL PublicURL) bool {
	if host == "" || strings.ContainsAny(host, "\r\n/\\@ ?#") {
		return false
	}
	name, ok := forwardedHostname(host)
	if !ok {
		return false
	}
	parent := strings.TrimPrefix(strings.ToLower(domain.String()), ".")
	if parent != "" {
		name = strings.ToLower(name)
		return name == parent || strings.HasSuffix(name, "."+parent)
	}
	allowed := publicURL.Host()
	publicScheme, _, _ := strings.Cut(publicURL.Origin(), "://")
	return allowed != "" && strings.EqualFold(withoutDefaultPort(scheme, host), withoutDefaultPort(publicScheme, allowed))
}

// defaultPorts is the port that a URL of each scheme has when it names none.
var defaultPorts = map[string]string{"http": ":80", "https": ":443"}

func withoutDefaultPort(scheme, host string) string {
	if port, ok := defaultPorts[strings.ToLower(scheme)]; ok {
		return strings.TrimSuffix(host, port)
	}
	return host
}

func forwardedHostname(hostport string) (string, bool) {
	if strings.HasPrefix(hostport, "[") {
		return bracketedHost(hostport)
	}
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		if strings.Contains(hostport, ":") {
			return "", false
		}
		return hostport, hostport != ""
	}
	if !validPort(port) || strings.Contains(host, ":") {
		return "", false
	}
	return host, true
}

func bracketedHost(hostport string) (string, bool) {
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		if !strings.HasSuffix(hostport, "]") || len(hostport) < 2 {
			return "", false
		}
		host = hostport[1 : len(hostport)-1]
		if !isIPv6(host) {
			return "", false
		}
		return host, true
	}
	if !validPort(port) || !isIPv6(host) {
		return "", false
	}
	return host, true
}

func isIPv6(host string) bool {
	ip := net.ParseIP(host)
	return ip != nil && ip.To4() == nil
}

func validPort(port string) bool {
	number, err := strconv.Atoi(port)
	return err == nil && number >= 1 && number <= 65535
}

// safeForwardedURI refuses a "://" in the path only: a query such as ?next=https://example.test/ is common.
func safeForwardedURI(uri string) bool {
	if !strings.HasPrefix(uri, "/") || strings.HasPrefix(uri, "//") {
		return false
	}
	path, _, _ := strings.Cut(uri, "?")
	path, _, _ = strings.Cut(path, "#")
	return !strings.ContainsAny(uri, "\r\n\\") && !strings.Contains(path, "://")
}
