package totp

import "uuid"

// EnrollmentID names one enrollment of a user. A new Begin gets a new id, so a request that
// read an older enrollment cannot change a newer one, even at the same version.
type EnrollmentID uuid.UUID

// NewEnrollmentID returns a random id.
func NewEnrollmentID() EnrollmentID {
	return EnrollmentID(uuid.New())
}

// EnrollmentIDFromBytes returns the id for the 16 UUID bytes.
func EnrollmentIDFromBytes(b [16]byte) EnrollmentID {
	return EnrollmentID(b)
}

// Bytes returns the 16-byte UUID form.
func (id EnrollmentID) Bytes() [16]byte {
	return uuid.UUID(id)
}
