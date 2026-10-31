package passwordstep

import "net/netip"

// ipv6NetworkBits is the IPv6 prefix that counts as one client.
// One host usually gets a whole /64, so a per-address count is easy to evade.
const ipv6NetworkBits = 64

// ClientIP is the address that a login attempt came from.
// The value is set only by NewClientIP.
type ClientIP struct {
	addr netip.Addr
}

// NewClientIP unmaps an IPv4-mapped IPv6 address and reduces IPv6 to its /64 network address.
func NewClientIP(addr netip.Addr) (ClientIP, error) {
	if !addr.IsValid() {
		return ClientIP{}, ErrInvalidClientIP
	}
	addr = addr.Unmap().WithZone("")
	if addr.Is4() {
		return ClientIP{addr: addr}, nil
	}
	prefix, err := addr.Prefix(ipv6NetworkBits)
	if err != nil {
		return ClientIP{}, ErrInvalidClientIP
	}
	return ClientIP{addr: prefix.Addr()}, nil
}

// Addr returns the stored address.
func (ip ClientIP) Addr() netip.Addr {
	return ip.addr
}

func (ip ClientIP) String() string {
	return ip.addr.String()
}
