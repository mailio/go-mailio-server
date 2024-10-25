package types

import "time"

// Errors that start with a 4 are temporary failures. No action is needed, the sender will try again.
// Errors that start with 5 are permanent failures and action is required to fix the problem.
// The error codes are adapted and re-modeled based on RFC3463 https://www.rfc-editor.org/rfc/rfc3463
var (
	/**  status-code = class "." subject "." detail

	class = "2"/"4"/"5"
	subject = 1*3digit
	detail = 1*3digit

	**/

	// 2.XXX.XXX   Success (e.g. successfull delivery 2.0.0)
	// 4.XXX.XXX   Temporary Failure
	// 5.XXX.XXX   Permanent Failure

	// System status codes
	ClassCodeSuccess     = 2 // The message has been delivered successfully
	ClassCodeTempFailure = 4 // The message has been temporarily failed
	ClassCodePermFailure = 5 // The message has been permanently failed

	// Subject codes
	SubjectCodeAccepted   = 0 // Accepted code indicates message has been accepted for delivery
	SubjectCodeAdressing  = 1 // Addressing status code The address status reports on the originator or destination address.  It may include address syntax or validity.  These errors can generally be corrected by the sender and retried.
	SubjectCodeMailbox    = 2 // Mailbox status code Mailbox status indicates that something having to do with the mailbox has caused this DSN.  Mailbox issues are assumed to be under the general control of the recipient.
	SubjectCodeMailSystem = 3 // Mail system status code Mail system status indicates that something having to do with the system has caused this DSN. System issues are assumed to be under the general control of the administrator.
	SubjectCodeNetwork    = 4 // Network and routing status code The networking or routing codes report status about the delivery system itself. These system components include any necessary infrastructure such as directory and routing services.
	SubjectCodeDelivery   = 5 // Mail delivery protocol status code The mail delivery protocol status codes report failures involving the message delivery protocol.  These failures include the full range of problems resulting from implementation errors or an unreliable connection.
	SubjectMessageContent = 6 // Message content or media status code The message content or media status codes report failures involving the content of the message.  These codes report failures due to translation, transcoding, or otherwise unsupported message media.
	SubjectSecurity       = 7 // Security or policy status code The security or policy status codes report failures involving policies such as per-recipient or per-host filtering and cryptographic operations.  Security and policy status issues are assumed to be under the control of either or both the sender and recipient.
	SubjectHandshake      = 8 // Message handshake status code. The message handshake status codes report failures involving the handshake of the message. This code can also report the placement of the message in the recipients mailbox folder.

	// Other or undefined status
	// X.0.0   Other undefined status

	// Addressing statuses
	// X.1.0   Other address status
	// X.1.1   Bad destination mailbox address
	// X.1.3   Bad destination mailbox address syntax
	// X.1.4   Destination mailbox address ambiguous
	// X.1.5   Destination address valid
	// X.1.6   Destination mailbox has moved, No forwarding address
	// X.1.7   Bad sender's mailbox address syntax
	// X.1.8   Bad sender's system address

	// Mailbox statuses
	// X.2.0   Other or undefined mailbox status
	// X.2.1   Mailbox disabled, not accepting messages
	// X.2.2   Mailbox full
	// X.2.3   Message length exceeds administrative limit
	// X.2.4   Mailing list expansion problem
	// X.2.5   Other or undefined mailbox status
	// X.2.6   Mailbox has moved
	// X.2.7   Bad sender's mailbox address syntax
	// X.2.8   Bad sender's system address

	// Mail system statuses
	// X.3.0   Other or undefined mail system status
	// X.3.1   Mail system full
	// X.3.2   System not accepting network messages
	// X.3.3   System not capable of selected features
	// X.3.4   Message too big for system
	// X.3.5   System incorrectly configured
	// X.3.6   Message content not accepted
	// X.3.7   Delivery time expired
	// X.3.8   Exceeded storage allocation
	// X.3.9   Authentication required

	// Network and routing statuses
	// X.4.0   Other or undefined network or routing status
	// X.4.1   No answer from host
	// X.4.2   Bad connection
	// X.4.3   Directory server failure (e.g. failed to connect to Internet DNS server)
	// X.4.4   Unable to route
	// X.4.5   Mail system congestion This is useful only as a persistent transient error.
	// X.4.6   Routing loop detected
	// X.4.7   Delivery time expired

	// Mail delivery protocol statuses
	// X.5.0   Other or undefined protocol status
	// X.5.1   Duplicate message ID
	// X.5.2  Syntax error
	// X.5.3   Too many recipients
	// X.5.4   Invalid command arguments
	// X.5.5   Wrong protocol version

	// Message content or media statuses
	// X.6.0   Other or undefined media error (Something about the content of a message caused it to be considered undeliverable)
	// X.6.1   Media not supported
	// X.6.2   Conversion required and prohibited
	// X.6.3   Conversion required but not supported
	// X.6.4   Conversion with loss performed
	// X.6.5   Conversion failed

	// Security or policy statuses
	// X.7.0   Other or undefined security status
	// X.7.1   Delivery not authorized, message refused (handshake revoked). This is useful only as a permanent error.
	// X.7.2   Mailing list expansion prohibited The sender is not authorized to send a message to the intended mailing list.  This is useful only as a permanent error.
	// X.7.3   Security conversion required but not possible (not needed)
	// X.7.4   Security features not supported
	// X.7.5   Signature keys invalid (necessary information such as key was not available or such information was invalid)
	// X.7.6   Signature algorithm not supported
	// X.7.7   Signature invalid (e.g. bad signature)

	// Handshake statuses
	// X.8.0   Other or undefined handshake status
	// X.8.1   Handshake failed (e.g. creating or lookup of a handshake failed)
	// X.8.2   Handshake revoked (user revoked handshake)
	// X.8.3   Handshake expired (handshake expired)
	// X.8.4   Handshake not supported (e.g. handshake not supported)
	// X.8.5   Handshake not possible (e.g. handshake not possible)
	// X.8.6   Handshake not available (e.g. handshake not available)
	// X.8.7   Handshake not verified (digital verification of handshake failed)
	// X.8.8   Handshake not completed (e.g. handshake not completed)
	// X.8.9   Handshake not found (e.g. handshake not found)
	// X.8.10  Handshake frequency exceeded
	// X.8.11  Handshake intent not supported
)

// Mailio Transfer Protocol (MTP) status codes
// e.g. for succesfull delivery 2.0.0
type MTPStatusCode struct {
	Class       int    `json:"class" validate:"required,oneof=2 4 5"`   // Represents the class of the status code (2, 4, 5)
	Subject     int    `json:"subject" validate:"required,min=0,max=8"` // Represents the subject category of the status code
	Detail      int    `json:"detail" validate:"required"`              // Represents the detail of the status code
	Description string `json:"description,omitempty"`                   // Human-readable message or description (optional)
	Address     string `json:"address,omitempty"`                       // Address of the recipient or sender
	Timestamp   int64  `json:"timestamp,omitempty"`                     // Unix timestamp in milliseconds
}

type MTPStatusCodeOption func(*MTPStatusCode)

func WithRecAddress(address string) MTPStatusCodeOption {
	return func(code *MTPStatusCode) {
		code.Address = address
	}
}

func NewMTPStatusCode(clazz int, subject int, detail int, description string, opts ...MTPStatusCodeOption) *MTPStatusCode {
	c := &MTPStatusCode{
		Class:       clazz,
		Subject:     subject,
		Detail:      detail,
		Description: description,
		Timestamp:   time.Now().UTC().UnixMilli(),
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}
