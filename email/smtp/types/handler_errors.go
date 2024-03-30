package mailiosmtp

import "fmt"

var (
	// ErrMailWebhookSignatureInvalid is returned when the webhook signature is invalid
	ErrMailWebhookSignatureInvalid = fmt.Errorf("invalid webhook signature")

	// ErrMailFailedSending is returned when the mail sending failed
	ErrMailFailedSending = fmt.Errorf("failed sending mail")

	// ErrMailParsingFailed is returned when the mail parsing failed
	ErrMailParsingFailed = fmt.Errorf("failed parsing mail")
)
