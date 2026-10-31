// Package identitylink keeps an outside account that is not linked to a user yet.
// A pending link never creates a user and never starts a session. A later password login
// in the same browser makes it an identity of that user. The provider is the identity kind.
package identitylink
