package api

import (
	"errors"
	"net"
	"net/http"
	"sort"
	"strings"

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
// scope is not a limit on a session. The bearer check uses token scopes.
type forwardAuthRequest struct {
	Scope string `query:"scope"`
	Group string `query:"group"`
}

func (s *service) forwardAuth(w http.ResponseWriter, r *http.Request) {
	if s.browser == nil || s.accounts == nil {
		loggerFrom(r.Context()).ErrorContext(r.Context(), "miniauth: auth check", "err", errors.New("api: auth check is not configured"))
		writeProblem(w, http.StatusInternalServerError, "The check failed.")
		return
	}
	sessionID, err := sessions.FromRequest(r)
	if err != nil {
		s.unauthenticated(w, r)
		return
	}
	session, _, err := s.browser.Open(r.Context(), sessionID)
	if errors.Is(err, sessions.ErrNotFound) {
		s.unauthenticated(w, r)
		return
	}
	if err != nil {
		loggerFrom(r.Context()).ErrorContext(r.Context(), "miniauth: auth check", "err", err)
		writeProblem(w, http.StatusInternalServerError, "The check failed.")
		return
	}
	account, err := s.accounts.Find(r.Context(), session.UserID)
	if errors.Is(err, users.ErrNotFound) {
		s.unauthenticated(w, r)
		return
	}
	if err != nil {
		loggerFrom(r.Context()).ErrorContext(r.Context(), "miniauth: auth check", "err", err)
		writeProblem(w, http.StatusInternalServerError, "The check failed.")
		return
	}
	have, err := s.groupNames(r, account.ID)
	if err != nil {
		loggerFrom(r.Context()).ErrorContext(r.Context(), "miniauth: auth check", "err", err)
		writeProblem(w, http.StatusInternalServerError, "The check failed.")
		return
	}
	need, ok := requiredGroups(r)
	if !ok || !hasGroups(have, need) {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	method := sessions.MethodFromFactors(session.Factors)
	if !writeAuthHeaders(w, account.Login, have, method) {
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
		w.Header().Set("Location", s.public.Login(returnURL(r, s.domain, s.public)))
		w.WriteHeader(http.StatusFound)
		return
	}
	w.Header().Set("WWW-Authenticate", "Bearer")
	w.WriteHeader(http.StatusUnauthorized)
}

func (s *service) groupNames(r *http.Request, userID users.ID) ([]groups.Name, error) {
	if s.members == nil {
		return nil, nil
	}
	return s.members.List(r.Context(), userID)
}

func requiredGroups(r *http.Request) ([]groups.Name, bool) {
	var need []groups.Name
	for _, raw := range r.URL.Query()["group"] {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
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
	user := login.String()
	email := emailFromLogin(login)
	groupsHeader := joinGroups(names)
	methodHeader := method.String()
	if !safeHeader(user) || !safeHeader(email) || !safeHeader(groupsHeader) || !safeHeader(methodHeader) {
		return false
	}
	w.Header().Set(headerAuthUser, user)
	w.Header().Set(headerAuthEmail, email)
	w.Header().Set(headerAuthGroups, groupsHeader)
	w.Header().Set(headerAuthMethod, methodHeader)
	return true
}

// emailFromLogin uses the login when it contains @.
// The account has no separate email column.
func emailFromLogin(login users.Login) string {
	value := login.String()
	if strings.Contains(value, "@") {
		return value
	}
	return ""
}

func joinGroups(names []groups.Name) string {
	ordered := append([]groups.Name(nil), names...)
	sort.Slice(ordered, func(i, j int) bool {
		return ordered[i].String() < ordered[j].String()
	})
	parts := make([]string, len(ordered))
	for i, name := range ordered {
		parts[i] = name.String()
	}
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
		media := strings.TrimSpace(part)
		if i := strings.IndexByte(media, ';'); i >= 0 {
			media = strings.TrimSpace(media[:i])
		}
		if strings.EqualFold(media, "text/html") {
			return true
		}
	}
	return false
}

func sessionCookiePresent(r *http.Request) bool {
	_, err := r.Cookie(sessions.CookieName)
	return err == nil
}

// returnURL is the page the browser asked Traefik for.
// The host must sit under the cookie domain.
// With no cookie domain, the host must be the public origin.
// Anything else is empty, so the login page gets no return query.
func returnURL(r *http.Request, domain sessions.Domain, public PublicURL) string {
	proto := strings.ToLower(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")))
	if proto != "http" && proto != "https" {
		return ""
	}
	host := strings.TrimSpace(r.Header.Get("X-Forwarded-Host"))
	if !forwardedHostAllowed(host, domain, public) {
		return ""
	}
	uri := r.Header.Get("X-Forwarded-Uri")
	if uri == "" {
		uri = "/"
	}
	if !safeForwardedURI(uri) {
		return ""
	}
	return proto + "://" + host + uri
}

func forwardedHostAllowed(host string, domain sessions.Domain, public PublicURL) bool {
	if host == "" || strings.ContainsAny(host, "\r\n/\\@ ") {
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
	allowed := public.Host()
	return allowed != "" && strings.EqualFold(host, allowed)
}

func forwardedHostname(hostport string) (string, bool) {
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return strings.Trim(h, "[]"), true
	}
	if strings.Contains(hostport, ":") {
		return "", false
	}
	return hostport, hostport != ""
}

func safeForwardedURI(uri string) bool {
	if !strings.HasPrefix(uri, "/") || strings.HasPrefix(uri, "//") {
		return false
	}
	if strings.ContainsAny(uri, "\r\n\\") || strings.Contains(uri, "://") {
		return false
	}
	return true
}
