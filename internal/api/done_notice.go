package api

import (
	"net/http"

	"github.com/popoffvg/miniauth/internal/views"
)

// doneFlag is the query flag of the redirect after a change. It carries no data.
type doneFlag string

const (
	doneResourceAdded        doneFlag = "resource-added"
	doneResourceDeleted      doneFlag = "resource-deleted"
	doneGranted              doneFlag = "granted"
	doneGrantRevoked         doneFlag = "revoked"
	doneTokenRevoked         doneFlag = "token-revoked"
	doneSignedOut            doneFlag = "signed-out"
	doneForgotten            doneFlag = "forgotten"
	donePasskeyDeleted       doneFlag = "passkey-deleted"
	doneTwoStepOff           doneFlag = "two-step-off"
	doneUserDisabled         doneFlag = "user-disabled"
	doneUserEnabled          doneFlag = "user-enabled"
	doneMemberAdded          doneFlag = "member-added"
	doneMemberRemoved        doneFlag = "member-removed"
	doneGroupCreated         doneFlag = "group-created"
	doneGroupDeleted         doneFlag = "group-deleted"
	doneGroupResourceAdded   doneFlag = "group-resource-added"
	doneGroupResourceRemoved doneFlag = "group-resource-removed"
	doneConsentRevoked       doneFlag = "consent-revoked"
)

// doneNotices is the fixed message of each flag. A page ignores a flag that is not in this list.
var doneNotices = []struct {
	flag    doneFlag
	message views.Message
}{
	{flag: doneResourceAdded, message: "The resource is added."},
	{flag: doneResourceDeleted, message: "The resource and its grants are deleted."},
	{flag: doneGranted, message: "The access is granted."},
	{flag: doneGrantRevoked, message: "The access is revoked."},
	{flag: doneTokenRevoked, message: "The token is revoked."},
	{flag: doneSignedOut, message: "The device is signed out."},
	{flag: doneForgotten, message: "The device is forgotten."},
	{flag: donePasskeyDeleted, message: "The passkey is deleted."},
	{flag: doneTwoStepOff, message: "Two-step login is off."},
	{flag: doneUserDisabled, message: "The user is disabled and signed out everywhere."},
	{flag: doneUserEnabled, message: "The user is enabled."},
	{flag: doneMemberAdded, message: "The user is added to the group."},
	{flag: doneMemberRemoved, message: "The user is removed from the group."},
	{flag: doneGroupCreated, message: "The group is created."},
	{flag: doneGroupDeleted, message: "The group, its memberships, and its grants are deleted."},
	{flag: doneGroupResourceAdded, message: "The group can now reach the resource."},
	{flag: doneGroupResourceRemoved, message: "The group no longer reaches the resource."},
	{flag: doneConsentRevoked, message: "The app is disconnected. Its tokens no longer work."},
}

func doneNotice(r *http.Request) views.Message {
	flag := doneFlag(r.URL.Query().Get("done"))
	for _, notice := range doneNotices {
		if notice.flag == flag {
			return notice.message
		}
	}
	return ""
}

func withDone(path string, flag doneFlag) string {
	return path + "?done=" + string(flag)
}
