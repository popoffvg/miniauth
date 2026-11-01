package views

import (
	"time"

	"github.com/popoffvg/miniauth/internal/devices"
	"github.com/popoffvg/miniauth/internal/groups"
	"github.com/popoffvg/miniauth/internal/loginflow"
	"github.com/popoffvg/miniauth/internal/providers/passkey"
	"github.com/popoffvg/miniauth/internal/users"
)

// SecurityView is the data of the security page. ShowPasskeys is false when the router has no passkey service.
type SecurityView struct {
	Shell        Shell
	Notice       Message
	Devices      []Device
	Passkeys     []passkey.Passkey
	ShowPasskeys bool
	TwoStep      TwoStep
}

// Device is one browser that signed in. IsCurrent marks the browser of this request.
type Device struct {
	ID        devices.ID
	Name      devices.Name
	FirstSeen time.Time
	LastSeen  time.Time
	IsCurrent bool
}

// TwoStep is the two-step login state that the security and the overview pages show.
type TwoStep struct {
	Shown     bool
	On        bool
	CanEnroll bool
}

// OverviewView is the data of the overview page. A count is shown only when its service is configured.
type OverviewView struct {
	Shell         Shell
	Groups        []groups.Name
	TwoStep       TwoStep
	ActiveTokens  int
	ShowTokens    bool
	Devices       int
	Passkeys      int
	ShowPasskeys  bool
	RecentDevices []Device
}

// LinkView is the data of the page that confirms a pending account link.
type LinkView struct {
	Login    users.Login
	Provider string
	Subject  users.Subject
	Return   loginflow.ReturnURL
}
