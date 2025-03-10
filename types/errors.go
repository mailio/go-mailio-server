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
	// ErrDomainNotFound - domain not found
	ErrDomainNotFound = errors.New("domain not found")

	// HANDSHAKE ERRORS
	// If handshake has been revoked
	ErrHandshakeRevoked = errors.New("handshake revoked")

	// Mailio Errors
	// ErrInvalidMailioAddress - invalid mailio address`
	ErrInvalidMailioAddress = errors.New("invalid mailio address")

	// ErrMxRecordCheckFailed - ony any error checking MX records
	ErrMxRecordCheckFailed = errors.New("mx record check failed")

	// ErrTooManyRequests - too many requests
	ErrTooManyRequests = errors.New("too many requests")

	// ErrNoRecipient - no recipient
	ErrNoRecipient = errors.New("no recipient")

	// ErrInvaidRecipient - invalid recipient
	ErrInvaidRecipient = errors.New("invalid recipient")

	// ErrInvalidSender - invalid sender
	ErrInvalidSender = errors.New("invalid sender")

	// ErrMessageTooLarge - message too large
	ErrMessageTooLarge = errors.New("message too large")

	// ErrTooManyAttachments - too many attachments
	ErrTooManyAttachments = errors.New("too many attachments")

	// ErrTooManyRecipients - too many recipients
	ErrTooManyRecipients = errors.New("too many recipients")

	// ErrBadRequestMissingSubjectOrBody - missing subject or body
	ErrBadRequestMissingSubjectOrBody = errors.New("missing subject or body")

	// ErrRecordExists - record exists
	ErrRecordExists = errors.New("record exists")
)
