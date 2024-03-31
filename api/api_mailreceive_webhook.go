package api

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	mailgunhandler "github.com/mailio/go-mailio-mailgun-smtp-handler"
	smtpmodule "github.com/mailio/go-mailio-server/email/smtp"
	smtptypes "github.com/mailio/go-mailio-server/email/smtp/types"
	"github.com/mailio/go-mailio-server/global"
	"github.com/mailio/go-mailio-server/services"
	"github.com/mailio/go-mailio-server/types"
)

var DENIED_FILE_EXTENSIONS = map[string]string{"ade": "ade", "adp": "adp", "apk": "apk", "appx": "appx", "appxbundle": "appxbundle", "bat": "bat", "cab": "cab", "chm": "chm", "cmd": "cmd", "com": "com", "cpl": "cpl", "dll": "dll", "dmg": "dmg", "ex": "ex", "ex_": "ex_", "exe": "exe", "hta": "hta", "ins": "ins", "isp": "isp", "iso": "iso", "jar": "jar", "js": "js", "jse": "jse", "lib": "lib", "lnk": "lnk", "mde": "mde", "msc": "msc", "msi": "msi", "msix": "msix", "msixbundle": "msixbundle", "msp": "msp", "mst": "mst", "nsh": "nsh", "pif": "pif", "ps1": "ps1", "scr": "scr", "sct": "sct", "shb": "shb", "sys": "sys", "vb": "vb", "vbe": "vbe", "vbs": "vbs", "vxd": "vxd", "wsc": "wsc", "wsf": "wsf", "wsh": "wsh"}

type MailReceiveWebhook struct {
	Environment      *types.Environment
	handshakeService *services.HandshakeService
	userService      *services.UserService
}

func NewMailReceiveWebhook(handshakeService *services.HandshakeService, userService *services.UserService, env *types.Environment) *MailReceiveWebhook {
	// Register the SMTP handlers (currently only mailgun)
	for _, wh := range global.Conf.MailWebhooks {
		if wh.Provider == "mailgun" {
			handler := mailgunhandler.NewMailgunSmtpHandler(wh.Sendapikey, wh.Domain)
			smtpmodule.RegisterSmtpHandler(wh.Provider, handler)
		}
	}
	return &MailReceiveWebhook{Environment: env, handshakeService: handshakeService, userService: userService}
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
	// finding the SMTP handler based on the path
	provider := fullPathToSmtpProvider(fullPath)
	smtpHandler := smtpmodule.GetHandler(provider)
	if smtpHandler == nil {
		c.JSON(501, gin.H{"error": fmt.Sprintf("SMTP handler %s not registered", provider)})
		return
	}
	// ReceiveMail - parsing of the email using the selected SMTP handler
	mail, mErr := smtpHandler.ReceiveMail(*c.Request)
	if mErr != nil {
		global.Logger.Log("error", mErr.Error())
		c.JSON(500, gin.H{"error": mErr.Error()})
		return
	}
	fmt.Printf("Received mail: %v\n", mail)

	// 1. Check email size (max 30 MB)
	if mail.SizeBytes > 30*1024*1024 {
		//TODO: send bounce
	}
	// 2. Check if the email is market as spam (to spam folder)
	if mail.SpamVerdict != nil && mail.SpamVerdict.Status == smtptypes.VerdictStatusFail {
		// TODO: save to spam folder
	}

	for _, att := range mail.Attachments {
		extension := filepath.Ext(att.Filename)
		extension = strings.ReplaceAll(extension, ".", "")
		if ext, isDenied := DENIED_FILE_EXTENSIONS[extension]; isDenied {
			global.Logger.Log("attachment filetype not allowed", att.ContentType, att.Filename, ext)
			//TODO: send bounce
		}
	}

	//TODO: thought: if initial checks are ok, then send the email to a queue (email ID) for further processing? (after attachments are stored to S3)
	// 1. Check handshake if exists (from the sacrypt mapping)
	for _, to := range mail.To {
		from := mail.From.Address

		userMapping, umErr := m.userService.FindUserByScryptEmail(to.Address)
		if umErr != nil {
			if umErr != types.ErrNotFound {
				global.Logger.Log("error", umErr.Error())
				continue
			}
		}

		// 3. Check if users is over the disk space here for each user

		// 6. Check based on stats to which folder the email should be stored
		toTimestamp := time.Now().UnixMilli()
		currentTime := time.UnixMilli(toTimestamp)
		sixMonthsAgo := currentTime.AddDate(0, -6, 0)
		fromTimestamp := sixMonthsAgo.UnixMilli() // 6 months ago
		countReceivedAll, cErr := m.userService.CountNumberOfReceivedMessages(mail.To[0].Address, from, false, fromTimestamp, toTimestamp)
		countReceivedRead, cErr := m.userService.CountNumberOfReceivedMessages(mail.To[0].Address, from, true, fromTimestamp, toTimestamp)
		countSent, cErr := m.userService.CountNumberOfSentMessages(mail.To[0].Address, fromTimestamp, toTimestamp)

		hs, hsErr := m.handshakeService.GetByMailioAddress(userMapping.MailioAddress, from)
		if hsErr != nil {
			if hsErr == types.ErrNotFound {
			} else {
				global.Logger.Log("error", hsErr.Error())
			}
		}
		if hs != nil && hs.Content.Status == types.HANDSHAKE_STATUS_ACCEPTED {
			// TODO: folder known
		}
	}

	// 7. Check if user is subscribed user??? (in the future - effects the disk space and the folder selection)
	// 8. Make sure the incoming email is for someone with the locally registered domain
	// 8.1. Make sure multiple domains are supported (web based initial config?)
}
