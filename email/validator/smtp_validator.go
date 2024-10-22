package validator

import (
	mailiosmtp "github.com/mailio/go-mailio-server/email/smtp/types"
)

type SmtpValidator interface {
	Validate(*mailiosmtp.Mail) error
}
