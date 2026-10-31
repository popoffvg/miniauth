package api

import (
	"net/http"
	"net/netip"

	"github.com/popoffvg/miniauth/internal/passwordstep"
)

// clientIP is the TCP peer of the request. X-Forwarded-For is not read, because no trusted
// proxy is configured: behind a proxy, every login shares the proxy address in the IP backoff.
func clientIP(r *http.Request) (passwordstep.ClientIP, error) {
	peer, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return passwordstep.ClientIP{}, passwordstep.ErrInvalidClientIP
	}
	return passwordstep.NewClientIP(peer.Addr())
}
