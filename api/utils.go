package api

import (
	"net/http"
	"net/mail"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/mailio/go-mailio-did/did"
	"github.com/mailio/go-mailio-server/api/interceptors"
	apiutil "github.com/mailio/go-mailio-server/api/util"
	smtptypes "github.com/mailio/go-mailio-server/email/smtp/types"
	"github.com/mailio/go-mailio-server/global"
	"github.com/mailio/go-mailio-server/types"
)

// set cookie in the response (httpOnly)
func setCookieAndGenerateToken(c *gin.Context, userDID *did.MailioKey, challenge string, usersPrimaryEd25519PublicKey string) (string, error) {
	token, tErr := interceptors.GenerateJWSToken(global.PrivateKey, userDID.DID(), global.MailioDID, challenge, usersPrimaryEd25519PublicKey)
	if tErr != nil {
		return "", tErr
	}

	domain, dErr := apiutil.GetIPFromContext(c)
	if dErr != nil {
		d := "localhost"
		domain = &d
	}
	secure := true
	if strings.Contains(*domain, "localhost") || strings.Contains(*domain, "::1") || strings.Contains(*domain, "127.0.0.1") {
		secure = false
		d := "localhost"
		domain = &d
	}

	cookie := http.Cookie{
		Name:     "__mailio-jws-token",
		Value:    token,
		Expires:  time.Now().Add(24 * 29 * time.Hour), // 29 days
		Path:     "/",
		Domain:   *domain,
		Secure:   secure,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}

	http.SetCookie(c.Writer, &cookie)

	return token, nil
}

// ConvertSMTP converts the input email to the required format for the SMTP Mailio interface.
// It takes an email as a parameter and returns the converted email format or an error.
//
// @param email - the email input to be converted
// @return - converted email format or an error if conversion fails
// Errors:
// - "invalid email address" if the FROM email address is invalid (ErrInvalidFormat)
// - "no address" if any invalid addressess are provided for recipients (to, cc, bcc) (ErrInvalidRecipient)
func convertToSmtpEmail(email types.SmtpEmailInput) (*smtptypes.Mail, error) {
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
