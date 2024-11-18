package util

import (
	"net"
	"net/mail"
	"strings"
	"time"

	smtptypes "github.com/mailio/go-mailio-server/email/smtp/types"
	"github.com/mailio/go-mailio-server/types"
)

func CheckMXRecords(domain string) (bool, error) {
	mxRecords, err := net.LookupMX(domain)
	if err != nil {
		return false, err
	}
	if len(mxRecords) > 0 {
		return true, nil
	}
	return false, nil
}

// ConvertFromSmtpEmail converts the input email to the required format for the SMTP Mailio interface.
// It takes an email as a parameter and returns the converted email format or an error.
func ConvertFromSmtpEmail(email *smtptypes.Mail) (*types.SmtpEmailInput, error) {
	// convert to smtp email
	var subject string
	var bodyHTML string
	var bodyText string
	var messageId string
	if email.Subject != "" {
		subject = email.Subject
	}
	if email.BodyHTML != "" {
		bodyHTML = email.BodyHTML
	}
	if email.BodyText != "" {
		bodyText = email.BodyText
	}
	if email.MessageId != "" {
		messageId = email.MessageId
	}
	if messageId == "" {
		return nil, types.ErrInvalidEmail
	}
	if IsNilOrEmpty(&email.From.Address) {
		return nil, types.ErrInvalidSender
	}
	from := email.From.String()

	tos := make([]string, len(email.To))
	for i, to := range email.To {
		tos[i] = to.String()
	}
	ccs := make([]*string, len(email.Cc))
	for i, cc := range email.Cc {
		str := cc.String()
		ccs[i] = &str
	}
	bccs := make([]*string, len(email.Bcc))
	for i, bcc := range email.Bcc {
		str := bcc.String()
		bccs[i] = &str
	}
	replysTo := make([]*string, len(email.ReplyTo))
	for i, r := range email.ReplyTo {
		str := r.String()
		replysTo[i] = &str
	}

	smtpEmail := &types.SmtpEmailInput{
		From:              from,
		To:                tos,
		ReplyTo:           replysTo,
		Cc:                ccs,
		Bcc:               bccs,
		Subject:           &subject,
		BodyHTML:          &bodyHTML,
		BodyText:          &bodyText,
		MessageId:         &messageId,
		Timestamp:         email.Timestamp,
		Attachments:       email.Attachments,
		DeleteAttachments: []string{},
	}
	// to recipient list
	for _, to := range email.To {
		smtpEmail.To = append(smtpEmail.To, to.Address)
	}
	// reply to mapping
	for _, r := range email.ReplyTo {
		smtpEmail.ReplyTo = append(smtpEmail.ReplyTo, &r.Address)
	}
	// cc
	for _, c := range email.Cc {
		smtpEmail.Cc = append(smtpEmail.Cc, &c.Address)
	}
	for _, b := range email.Bcc {
		smtpEmail.Bcc = append(smtpEmail.Bcc, &b.Address)
	}
	return smtpEmail, nil
}

// ConvertSMTP converts the input email to the required format for the SMTP Mailio interface.
// It takes an email as a parameter and returns the converted email format or an error.
//
// param email - the email input to be converted
// return - converted email format or an error if conversion fails
// Errors:
// - "invalid email address" if the FROM email address is invalid (ErrInvalidFormat)
// - "no address" if any invalid addressess are provided for recipients (to, cc, bcc) (ErrInvalidRecipient)
func ConvertToSmtpEmail(email types.SmtpEmailInput) (*smtptypes.Mail, error) {
	// convert to smtp email
	from, fErr := mail.ParseAddress(email.From)
	if fErr != nil {
		return nil, types.ErrInvalidFormat
	}
	// to recipient list
	tos, tErr := mail.ParseAddressList(strings.Join(email.To, ","))
	if tErr != nil {
		if strings.Contains(tErr.Error(), "no address") {
			return nil, types.ErrInvaidRecipient
		}
		return nil, tErr
	}
	// convert to no pointer
	noPointerTos := make([]mail.Address, len(tos))
	for i, to := range tos {
		noPointerTos[i] = *to
	}
	// reply to mapping
	var replyTo []*mail.Address
	if len(email.ReplyTo) > 0 {
		for _, r := range email.ReplyTo {
			rTo, rtErr := mail.ParseAddress(*r)
			if rtErr != nil {
				return nil, types.ErrInvaidRecipient
			}
			replyTo = append(replyTo, rTo)
		}
	}
	// cc
	var cc []*mail.Address
	if len(email.Cc) > 0 {
		for _, c := range email.Cc {
			ccs, ccErr := mail.ParseAddress(*c)
			if ccErr != nil {
				return nil, types.ErrInvaidRecipient
			}
			cc = append(cc, ccs)
		}
	}
	var bcc []*mail.Address
	if len(email.Bcc) > 0 {
		for _, b := range email.Bcc {
			bccs, bccErr := mail.ParseAddress(*b)
			if bccErr != nil {
				return nil, types.ErrInvaidRecipient
			}
			bcc = append(bcc, bccs)
		}
	}

	// no need to strip unsafe tags and convert html to text since it is done in the email queue service
	smtpEmail := &smtptypes.Mail{
		From:        *from,
		To:          noPointerTos,
		BodyHTML:    *email.BodyHTML,
		ReplyTo:     replyTo,
		Cc:          cc,
		Bcc:         bcc,
		Timestamp:   time.Now().UTC().UnixMilli(),
		Subject:     *email.Subject,
		Attachments: email.Attachments,
	}
	return smtpEmail, nil
}
