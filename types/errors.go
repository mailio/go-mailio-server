package types

import "errors"

var (
	// ErrInvalidEmail is returned when the email is invalid
	ErrInvalidEmail = errors.New("invalid email address")

	// ErrInvalidPassword is returned when the password is invalid
	ErrUserExists = errors.New("user exists")
)
