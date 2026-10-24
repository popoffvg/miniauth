// Package migrations holds the numbered goose SQL files, embedded in the binary.
package migrations

import "embed"

// FS MUST only gain new files: a file that is on main never changes.
//
//go:embed *.sql
var FS embed.FS
