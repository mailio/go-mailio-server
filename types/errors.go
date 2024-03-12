package types

import "errors"

var (
	// ErrInvalidEmail is returned when the email is invalid
	ErrInvalidEmail = errors.New("invalid email address")
	// ErrInternal (for unahandled exceptions)
	ErrInternal = errors.New("internal errior")
	// ErrConflict is returned when the resource conflicts (e.g. update of old revision)
	ErrConflict = errors.New("conflict")
	// ErrNotFound is returned when a resource is not found.
	ErrNotFound = errors.New("not found")
	// ErrTimeout is returned when a timeout occurs.
	ErrTimeout = errors.New("timeout")
	// ErrInvalidFormat is returned when a resource is not in the expected format.
	ErrInvalidFormat = errors.New("invalid format")
	// operation not authorized
	ErrUnauthorized = errors.New("unauthorized")
	// ErrNotAuthorized - authorization failed
	ErrNotAuthorized = errors.New("not authorized")
	// ErrUserExists - user already exists
	ErrUserExists = errors.New("user exists")
	// ErrUnimoplemented - unimplemented
	ErrUnimplemented = errors.New("unimplemented")
	// ErrBadRequest - bad request (or invalid input data)
	ErrBadRequest = errors.New("bad request")
	// ErrQuotaExceeded - quota exceeded
	ErrQuotaExceeded = errors.New("quota exceeded")
	// expired trial
	ErrTrialExpired = errors.New("trial has expired")
	// ErrRateLimitExceeded - rate limit exceeded
	ErrRateLimitExceeded = errors.New("rate limit exceeded")
	// ErrInvalidPublicKey - invalid public key
	ErrInvalidPublicKey = errors.New("invalid public key")
	// ErrInvalidSignature - invalid signature
	ErrSignatureInvalid = errors.New("signature invalid")
	// ErrInvalidPrivateKey - invalid private key
	ErrInvalidPrivateKey = errors.New("invalid private key")
	// ErrContinue defines something went wrong but code exection should continue
	ErrContinue = errors.New("continue")

	// HANDSHAKE ERRORS
	// If handshake has been revoked
	ErrHandshakeRevoked = errors.New("handshake revoked")
)
