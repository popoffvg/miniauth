// Package identitylink keeps an outside account that is not linked to a user yet.
// A pending link never creates a user and never starts a session. After a later password login
// in the same browser, the user confirms the link on a page that names the account.
// Only then it becomes an identity. The provider is the identity kind.
package identitylink
