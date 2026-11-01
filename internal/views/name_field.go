package views

import "strconv"

// nameFieldLength is the maxlength of a field for a name of at most runes characters.
// A browser counts maxlength in UTF-16 units, and a character outside the BMP is two units.
func nameFieldLength(runes int) string {
	return strconv.Itoa(2 * runes)
}
