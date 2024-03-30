package api

import (
	"fmt"

	"github.com/gin-gonic/gin"
	mailgunhandler "github.com/mailio/go-mailio-mailgun-smtp-handler"
	smtpmodule "github.com/mailio/go-mailio-server/email/smtp"
	"github.com/mailio/go-mailio-server/global"
	"github.com/mailio/go-mailio-server/types"
)

type MailReceiveWebhook struct {
	Environment *types.Environment
}

func NewMailReceiveWebhook(env *types.Environment) *MailReceiveWebhook {
	// Register the SMTP handlers (currently only mailgun)
	for _, wh := range global.Conf.MailWebhooks {
		if wh.Provider == "mailgun" {
			handler := mailgunhandler.NewMailgunSmtpHandler(wh.Sendapikey, wh.Domain)
			smtpmodule.RegisterSmtpHandler(wh.Provider, handler)
		}
	}
	return &MailReceiveWebhook{Environment: env}
}

// converts a path to smtp provider (e.g. /webhook/mailgun_mime -> mailgun)
func fullPathToSmtpProvider(fullPath string) string {
	provider := ""
	for _, wh := range global.Conf.MailWebhooks {
		if wh.Webhookurl == fullPath {
			provider = wh.Provider
			break
		}
	}
	return provider
}

// ReceiveMail webhook implementations
func (m *MailReceiveWebhook) ReceiveMail(c *gin.Context) {
	fullPath := c.FullPath()
	handlers := smtpmodule.Handlers()
	if len(handlers) == 0 {
		c.JSON(501, gin.H{"error": "No SMTP handler registered"})
		return
	}
	provider := fullPathToSmtpProvider(fullPath)
	smtpHandler := smtpmodule.GetHandler(provider)
	if smtpHandler == nil {
		c.JSON(501, gin.H{"error": fmt.Sprintf("SMTP handler %s not registered", provider)})
		return
	}
	mail, mErr := smtpHandler.ReceiveMail(*c.Request)
	if mErr != nil {
		global.Logger.Log("error", mErr.Error())
		c.JSON(500, gin.H{"error": mErr.Error()})
		return
	}
	fmt.Printf("Received mail: %v\n", mail)
	// TODO! check the mailserver implementation
	//TODO: thought: if initial checks are ok, then send the email to a queue (email ID) for further processing? (after attachments are stored to S3)
	// 1. Check handshake if exists (from the sacrypt mapping)
	// 2. Check email size (max 30 MB)
	// 3. Check if the email is market as spam (to spam folder)
	// 4. Check for attachments (if allowed or not). If allowed store to S3 bucket
	// 5. Check if users is over the disk space
	// 6. Check based on stats to which folder the email should be stored
	// 7. Check if user is subscribed user??? (in the future - effects the disk space and the folder selection)
	// 8. Make sure the incoming email is for someone with the locally registered domain
	// 8.1. Make sure multiple domains are supported (web based initial config?)
}
