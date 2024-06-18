package api

import (
	"fmt"
	"net/http"
	"net/mail"
	"path/filepath"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/hibiken/asynq"
	smtpmodule "github.com/mailio/go-mailio-server/email/smtp"
	smtptypes "github.com/mailio/go-mailio-server/email/smtp/types"
	"github.com/mailio/go-mailio-server/global"
	"github.com/mailio/go-mailio-server/services"
	"github.com/mailio/go-mailio-server/types"
	"github.com/mailio/go-mailio-server/util"
)

var DENIED_FILE_EXTENSIONS = map[string]string{"ade": "ade", "adp": "adp", "apk": "apk", "appx": "appx", "appxbundle": "appxbundle", "bat": "bat", "cab": "cab", "chm": "chm", "cmd": "cmd", "com": "com", "cpl": "cpl", "dll": "dll", "dmg": "dmg", "ex": "ex", "ex_": "ex_", "exe": "exe", "hta": "hta", "ins": "ins", "isp": "isp", "iso": "iso", "jar": "jar", "js": "js", "jse": "jse", "lib": "lib", "lnk": "lnk", "mde": "mde", "msc": "msc", "msi": "msi", "msix": "msix", "msixbundle": "msixbundle", "msp": "msp", "mst": "mst", "nsh": "nsh", "pif": "pif", "ps1": "ps1", "scr": "scr", "sct": "sct", "shb": "shb", "sys": "sys", "vb": "vb", "vbe": "vbe", "vbs": "vbs", "vxd": "vxd", "wsc": "wsc", "wsf": "wsf", "wsh": "wsh"}

type MailReceiveWebhook struct {
	env                *types.Environment
	handshakeService   *services.HandshakeService
	userService        *services.UserService
	userProfileService *services.UserProfileService
}

func NewMailReceiveWebhook(handshakeService *services.HandshakeService, userService *services.UserService, userProfileService *services.UserProfileService, env *types.Environment) *MailReceiveWebhook {
	return &MailReceiveWebhook{env: env, handshakeService: handshakeService, userService: userService, userProfileService: userProfileService}
}

// converts a path to smtp provider (e.g. /webhook/mailgun_mime -> mailgun)
func fullPathToSupportedDomains(fullPath string) []*global.MailDomains {
	mailDomains := []*global.MailDomains{}
	for _, wh := range global.Conf.SmtpServers {
		if wh.Webhookurl == fullPath {
			mailDomains = append(mailDomains, wh.Domains...)
			break
		}
	}
	return mailDomains
}

// ReceiveMail webhook implementations
// @Summary Receive a new SMTP email
// @Description Receive a new SMTP email
// @Tags Smtp Webhook Handler
// @Accept json
// @Produce json
// @Success 200
// @Failure 401 {object} api.ApiError "invalid signature/not authorized"
// @Failure 400 {object} api.ApiError "bad request"
// @Failure 500 {object} api.ApiError "internal error"
// @Router /webhook/mailgun_mime [post]
func (m *MailReceiveWebhook) ReceiveMail(c *gin.Context) {
	fullPath := c.FullPath()
	handlers := smtpmodule.Handlers()
	if len(handlers) == 0 {
		c.JSON(http.StatusNotImplemented, gin.H{"error": "No SMTP handler registered"})
		return
	}
	// finding the SMTP handler based on the path
	supportedDomains := fullPathToSupportedDomains(fullPath)
	if len(supportedDomains) == 0 {
		c.JSON(http.StatusBadGateway, gin.H{"error": "SMTP handler not found"})
		return
	}
	// doesn't matter for which domain is the handler as long as it's for the appropriate provider
	smtpHandler := smtpmodule.GetHandler(supportedDomains[0].Domain)
	if smtpHandler == nil {
		c.JSON(http.StatusNotImplemented, gin.H{"error": fmt.Sprintf("SMTP handler %s not registered", supportedDomains[0].Domain)})
		return
	}

	// ReceiveMail - parsing of the email using the selected SMTP handler
	email, mErr := smtpHandler.ReceiveMail(*c.Request)
	if mErr != nil {
		global.Logger.Log("error parsing mime", mErr.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"error parsing mime": mErr.Error()})
		return
	}
	// fmt.Printf("Received mail: %v\n", email.MessageId)
	global.Logger.Log("Received mail webhook call for message id: ", email.MessageId)

	// Check if too many recipients
	if len(email.To) > 100 {
		// send bounce
		global.Logger.Log("too many recipients", len(email.To))
		sendBounce(email, c, smtpHandler, "4.5.3", "Too many recipients")
		return
	}
	// Check email size (max 30 MB)
	if email.SizeBytes > 30*1024*1024 {
		// send bounce
		sendBounce(email, c, smtpHandler, "5.3.4", "Email size is too large")
		return
	}
	// limit number of attachments
	if len(email.Attachments) > 100 {
		sendBounce(email, c, smtpHandler, "5.3.4", "Too many attachments")
		return
	}
	// limit numbe of online attachments
	if len(email.BodyInlinePart) > 100 {
		sendBounce(email, c, smtpHandler, "5.3.4", "Too many inline attachments")
		return
	}
	// 3 MB limit for email body without inline attachments and other attachments
	if len([]byte(email.BodyHTML)) > 3*1024*1024 || len([]byte(email.BodyText)) > 3*1024*1024 {
		sendBounce(email, c, smtpHandler, "5.3.4", "Email body size is too large")
		return
	}

	// check if attachments are allowed
	for _, att := range email.Attachments {
		extension := filepath.Ext(att.Filename)
		extension = strings.ReplaceAll(extension, ".", "")
		if ext, isDenied := DENIED_FILE_EXTENSIONS[extension]; isDenied {
			global.Logger.Log("attachment filetype not allowed", att.ContentType, att.Filename, ext)
			// send bounce
			sendBounce(email, c, smtpHandler, "5.7.1", fmt.Sprintf("Attachment filetype not allowed: %s", ext))
			return
		}
	}

	// add to queue
	task := &types.SmtpTask{
		Mail: email,
		// SmtpProvider: provider,
	}
	receiveTask, tErr := types.NewSmtpCommReceiveTask(task)
	if tErr != nil {
		ApiErrorf(c, http.StatusInternalServerError, tErr.Error())
		return
	}
	email.Timestamp = time.Now().UTC().UnixMilli()
	id, idErr := util.SmtpMailToUniqueID(email, types.MailioFolderInbox)
	if idErr != nil {
		ApiErrorf(c, http.StatusBadRequest, idErr.Error())
		return
	}

	// add to task queue
	taskInfo, tqErr := m.env.TaskClient.Enqueue(receiveTask,
		asynq.MaxRetry(3),              // max number of times to retry the task
		asynq.Timeout(600*time.Second), // max time to process the task
		asynq.TaskID(id),               // unique task id
		asynq.Unique(time.Second*10))   // unique for 10 seconds (preventing multiple equal messages in the queue)
	if tqErr != nil {
		global.Logger.Log(tqErr.Error(), "failed to receive message")
		ApiErrorf(c, http.StatusInternalServerError, "failed to receive message")
		return
	}

	global.Logger.Log(fmt.Sprintf("message SMTP received: %s", taskInfo.ID), "message queued")
	c.JSON(200, gin.H{"message": "email queued succesfully under id: " + taskInfo.ID})
}

// sendBounce sends a bounce email to the sender of the email
func sendBounce(email *smtptypes.Mail, c *gin.Context, smtpHandler smtpmodule.SmtpHandler, code, message string) {
	bounceMail, bErr := smtpmodule.ToBounce(email.From, *email, code, message, global.Conf.Mailio.ServerDomain)
	if bErr != nil {
		global.Logger.Log("error", bErr.Error())
		ApiErrorf(c, 500, fmt.Sprintf("error creating bounce email: %s", bErr.Error()))
		return
	}
	_, sndErr := smtpHandler.SendMimeMail(email.From, bounceMail, []mail.Address{email.From})
	if sndErr != nil {
		global.Logger.Log("error sending bounce email", sndErr.Error())
		ApiErrorf(c, 500, fmt.Sprintf("error sending bounce email: %s", sndErr.Error()))
	}
	c.JSON(200, gin.H{"message": "Email size is too large"})
}
