package password

import (
	"errors"
	"net/netip"
	"testing"
)

func TestNewClientIP(t *testing.T) {
	tests := []struct {
		raw  string
		want string
	}{
		{raw: "192.0.2.7", want: "192.0.2.7"},
		{raw: "::ffff:192.0.2.7", want: "192.0.2.7"},
		{raw: "2001:db8:1:2:3:4:5:6", want: "2001:db8:1:2::"},
		{raw: "fe80::1%eth0", want: "fe80::"},
	}
	for _, tt := range tests {
		ip, err := NewClientIP(netip.MustParseAddr(tt.raw))
		if err != nil {
			t.Fatalf("NewClientIP(%s) error = %v", tt.raw, err)
		}
		if ip.String() != tt.want {
			t.Errorf("NewClientIP(%s) = %s, want %s", tt.raw, ip, tt.want)
		}
	}
	if _, err := NewClientIP(netip.Addr{}); !errors.Is(err, ErrInvalidClientIP) {
		t.Fatalf("zero address error = %v", err)
	}
}
