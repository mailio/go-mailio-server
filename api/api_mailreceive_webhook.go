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
	// only mailgun currently supported
	if global.Conf.MailWebhookConfig.Provider == "mailgun" {
		apiKey := global.Conf.MailWebhookConfig.Sendapikey
		domain := global.Conf.MailWebhookConfig.Domain
		handler := mailgunhandler.NewMailgunSmtpHandler(apiKey, domain)
		smtpmodule.RegisterSmtpHandler(global.Conf.MailWebhookConfig.Provider, handler)
	}
	return &MailReceiveWebhook{Environment: env}
}

// ReceiveMail webhook implementation based on
func (m *MailReceiveWebhook) ReceiveMail(c *gin.Context) {
	handlers := smtpmodule.Handlers()
	if len(handlers) == 0 {
		c.JSON(501, gin.H{"error": "No SMTP handler registered"})
		return
	}
	smtpHandler := smtpmodule.GetHandler(global.Conf.MailWebhookConfig.Provider)
	if smtpHandler == nil {
		c.JSON(501, gin.H{"error": fmt.Sprintf("SMTP handler %s not registered", global.Conf.MailWebhookConfig.Provider)})
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
	// 1. Check handshake if exists (from the sacrypt mapping)
	// 2. Check if the email is market as spam (to spam folder)
	// 3. Check email size (max 30 MB)
	// 4. Check if users is over the disk space
	// 5. Check if user is subscribed user?
}
