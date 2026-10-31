package api

import (
	"errors"
	"net/http"
	"slices"
	"time"

	"github.com/popoffvg/miniauth/internal/devices"
	"github.com/popoffvg/miniauth/internal/groups"
	"github.com/popoffvg/miniauth/internal/sessions"
	"github.com/popoffvg/miniauth/internal/users"
)

// recentDeviceCount is how many devices the overview lists.
const recentDeviceCount = 3

// overviewView is the data of the overview page. A count is shown only when its service is configured.
type overviewView struct {
	Shell         shellView
	Groups        []groups.Name
	TwoStep       twoStepView
	ActiveTokens  int
	ShowTokens    bool
	Devices       int
	Passkeys      int
	ShowPasskeys  bool
	RecentDevices []deviceView
}

// home is the overview page, the default page after a login. A disabled user is signed out here, as in /auth/check.
func (s *service) home(w http.ResponseWriter, r *http.Request) {
	session, err := s.openBrowserSession(r)
	if errors.Is(err, sessions.ErrNotFound) {
		http.Redirect(w, r, s.publicURL.Login(""), http.StatusFound)
		return
	}
	if err != nil {
		loggerFrom(r.Context()).ErrorContext(r.Context(), "miniauth: home", "err", err)
		renderDenied(w, r, http.StatusInternalServerError, msgLoginFailed)
		return
	}
	user, err := s.accounts.Find(r.Context(), session.UserID)
	if errors.Is(err, users.ErrNotFound) || err == nil && user.Disabled() {
		http.Redirect(w, r, s.publicURL.Login(""), http.StatusFound)
		return
	}
	if err != nil {
		loggerFrom(r.Context()).ErrorContext(r.Context(), "miniauth: home", "err", err)
		renderDenied(w, r, http.StatusInternalServerError, msgLoginFailed)
		return
	}
	view, err := s.overviewOf(r, user, session)
	if err != nil {
		loggerFrom(r.Context()).ErrorContext(r.Context(), "miniauth: home", "err", err)
		renderDenied(w, r, http.StatusInternalServerError, msgLoginFailed)
		return
	}
	writePage(w, r, http.StatusOK, overviewPage(view), pageCSP)
}

func (s *service) overviewOf(r *http.Request, user users.User, session sessions.Session) (overviewView, error) {
	ctx := r.Context()
	names, err := s.groups.List(ctx, user.ID)
	if err != nil {
		return overviewView{}, err
	}
	view := overviewView{
		Shell:  shellView{Login: user.Login, Admin: slices.Contains(names, groups.Admin()), Current: "/"},
		Groups: names,
	}
	if view.TwoStep, err = s.twoStepView(r, user.ID); err != nil {
		return overviewView{}, err
	}
	if s.tokens != nil {
		list, listErr := s.tokens.List(ctx, user.ID)
		if listErr != nil {
			return overviewView{}, listErr
		}
		now := time.Now()
		view.ShowTokens = true
		for _, token := range list {
			if statusOf(token, now) == tokenActive {
				view.ActiveTokens++
			}
		}
	}
	if s.passkeys != nil {
		list, listErr := s.passkeys.List(ctx, user.ID)
		if listErr != nil {
			return overviewView{}, listErr
		}
		view.ShowPasskeys = true
		view.Passkeys = len(list)
	}
	list, err := s.browser.Devices(ctx, user.ID)
	if err != nil {
		return overviewView{}, err
	}
	view.Devices = len(list)
	for _, device := range list {
		view.RecentDevices = append(view.RecentDevices, deviceView{
			ID:        device.ID,
			Name:      device.Name,
			FirstSeen: device.FirstSeen.UTC(),
			LastSeen:  device.LastSeen.UTC(),
			IsCurrent: session.DeviceID != (devices.ID{}) && device.ID == session.DeviceID,
		})
	}
	slices.SortFunc(view.RecentDevices, func(a, b deviceView) int { return b.LastSeen.Compare(a.LastSeen) })
	view.RecentDevices = view.RecentDevices[:min(len(view.RecentDevices), recentDeviceCount)]
	return view, nil
}
