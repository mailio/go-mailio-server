package types

import (
	smtptypes "github.com/mailio/go-mailio-server/email/smtp/types"
)

// for login
type InputLogin struct {
	Email                         string `json:"email" validate:"required,email"`
	MailioAddress                 string `json:"mailioAddress" validate:"required"`
	Nonce                         string `json:"nonce" validate:"required"`
	Ed25519SigningPublicKeyBase64 string `json:"ed25519SigningPublicKeyBase64" validate:"required"` // public key of the private key used to sign the nonce
	SignatureBase64               string `json:"signatureBase64" validate:"required"`               // signature of Nonce string
}

// for register
type InputRegister struct {
	InputLogin
	DatabasePassword      string `json:"databasePassword" validate:"required"`      // this is a password for couchdbs private user database
	X25519PublicKeyBase64 string `json:"x25519PublicKeyBase64" validate:"required"` // public encryption key
}

// for DID resolution
type InputDID struct {
	DID string `json:"did" validate:"required"`
}

type InputHandshakeLookup struct {
	Lookups []HandshakeLookup `json:"lookups" validate:"min=1"`
}

type InputDIDLookup struct {
	Lookups []*DIDLookup `json:"lookups" validate:"min=1"`
}

type SmtpEmailInput struct {
	From        string                      `json:"from"`                // The email address of the original sender.
	ReplyTo     []*string                   `json:"replyTo,omitempty"`   // The email address to which bounces (undeliverable notifications) are to be forwarded.
	To          []string                    `json:"to"`                  // The email addresses of the recipients.
	Cc          []*string                   `json:"cc,omitempty"`        // The email addresses of the CC recipients.
	Bcc         []*string                   `json:"bcc,omitempty"`       // The email addresses of the BCC recipients.
	MessageId   *string                     `json:"messageId,omitempty"` // message id
	Subject     *string                     `json:"subject,omitempty"`
	BodyText    *string                     `json:"bodyText,omitempty"` // The text version of the email.
	BodyHTML    *string                     `json:"bodyHtml,omitempty"` // The HTML version of the email.
	Attachments []*smtptypes.SmtpAttachment `json:"attachments,omitempty"`
}
