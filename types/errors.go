package types

import "errors"

var (
	// ErrInvalidEmail is returned when the email is invalid
	ErrInvalidEmail = errors.New("invalid email address")

	// ErrInternal (for unahandled exceptions)
	ErrInternal = errors.New("internal errior")

	// ErrConflict is returned when the resource conflicts (e.g. update of old revision)
	ErrConflict = errors.New("conflict")
)
