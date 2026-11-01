package groups

// Admins is the built-in group whose members open the admin pages.
func Admins() Name {
	return Name{value: "admins"}
}

// Users is the built-in group that every account joins when it is created.
func Users() Name {
	return Name{value: "users"}
}

// BuiltIn reports whether name is a group that always exists and cannot be deleted.
func (n Name) BuiltIn() bool {
	return n == Admins() || n == Users()
}
