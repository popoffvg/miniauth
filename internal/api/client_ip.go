package api

import (
	"net/http"
	"net/netip"

	"github.com/popoffvg/miniauth/internal/providers/password"
)

// clientIP is the TCP peer of the request. X-Forwarded-For is not read, because no trusted
// proxy is configured: behind a proxy, every login shares the proxy address in the IP backoff.
func clientIP(r *http.Request) (password.ClientIP, error) {
	peer, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return password.ClientIP{}, password.ErrInvalidClientIP
	}
	return password.NewClientIP(peer.Addr())
}
