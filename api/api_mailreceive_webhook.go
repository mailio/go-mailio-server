package api

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/mail"
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
	"github.com/mailio/go-mailio-server/util"
)

var DENIED_FILE_EXTENSIONS = map[string]string{"ade": "ade", "adp": "adp", "apk": "apk", "appx": "appx", "appxbundle": "appxbundle", "bat": "bat", "cab": "cab", "chm": "chm", "cmd": "cmd", "com": "com", "cpl": "cpl", "dll": "dll", "dmg": "dmg", "ex": "ex", "ex_": "ex_", "exe": "exe", "hta": "hta", "ins": "ins", "isp": "isp", "iso": "iso", "jar": "jar", "js": "js", "jse": "jse", "lib": "lib", "lnk": "lnk", "mde": "mde", "msc": "msc", "msi": "msi", "msix": "msix", "msixbundle": "msixbundle", "msp": "msp", "mst": "mst", "nsh": "nsh", "pif": "pif", "ps1": "ps1", "scr": "scr", "sct": "sct", "shb": "shb", "sys": "sys", "vb": "vb", "vbe": "vbe", "vbs": "vbs", "vxd": "vxd", "wsc": "wsc", "wsf": "wsf", "wsh": "wsh"}

type MailReceiveWebhook struct {
	Environment        *types.Environment
	handshakeService   *services.HandshakeService
	userService        *services.UserService
	userProfileService *services.UserProfileService
}

func NewMailReceiveWebhook(handshakeService *services.HandshakeService, userService *services.UserService, userProfileService *services.UserProfileService, env *types.Environment) *MailReceiveWebhook {
	// Register the SMTP handlers (currently only mailgun)
	for _, wh := range global.Conf.MailWebhooks {
		if wh.Provider == "mailgun" {
			handler := mailgunhandler.NewMailgunSmtpHandler(wh.Sendapikey, wh.Domain)
			smtpmodule.RegisterSmtpHandler(wh.Provider, handler)
		}
	}
	return &MailReceiveWebhook{Environment: env, handshakeService: handshakeService, userService: userService, userProfileService: userProfileService}
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
		c.JSON(501, gin.H{"error": "No SMTP handler registered"})
		return
	}
	// finding the SMTP handler based on the path
	provider := fullPathToSmtpProvider(fullPath)
	smtpHandler := smtpmodule.GetHandler(provider)
	if smtpHandler == nil {
		c.JSON(http.StatusNotImplemented, gin.H{"error": fmt.Sprintf("SMTP handler %s not registered", provider)})
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
	global.Logger.Log("Received mail", email.MessageId)

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

	// 2. Check if the email is market as spam (to spam folder)
	isSpam := false
	if email.SpamVerdict != nil && email.SpamVerdict.Status == smtptypes.VerdictStatusFail {
		// save to spam folder for all recipients
		isSpam = true
	}

	//TODO: thought: if initial checks are ok, then send the email to a queue (email ID) for further processing? (after attachments are stored to S3)
	// 1. Check handshake if exists (from the sacrypt mapping)
	allTo := []string{}
	for _, to := range email.To {
		allTo = append(allTo, to.String())
	}
	for _, to := range email.To {
		from := email.From.Address

		userMapping, umErr := m.userService.FindUserByScryptEmail(to.Address)
		if umErr != nil {
			if umErr != types.ErrNotFound {
				global.Logger.Log("error", umErr.Error())
				sendBounce(email, c, smtpHandler, "5.1.1", fmt.Sprintf("Recipient not found: %s", to.Address))
				continue
			}
		}
		// retrieve users profile
		userProfile, upErr := m.userProfileService.Get(userMapping.MailioAddress)
		if upErr != nil {
			global.Logger.Log("error", upErr.Error())
			ApiErrorf(c, 500, fmt.Sprintf("error getting user profile: %s", upErr.Error()))
			return
		}
		// 3. Check if users is over the disk space limit
		//TODO!: also include S3 storage in the calculation!
		stats, sErr := m.userProfileService.Stats(userMapping.MailioAddress)
		if sErr != nil {
			global.Logger.Log("error retrieving disk usage stats", sErr.Error())
			ApiErrorf(c, http.StatusInternalServerError, fmt.Sprintf("error retrieving disk usage stats: %s", sErr.Error()))
			return
		}
		// check if user over quota
		if stats.FileSize > userProfile.DiskSpace {
			sendBounce(email, c, smtpHandler, "5.2.2", "Over disk space limit")
			return
		}

		// determine to which users folder to save incoming email
		folder := types.MailioFolderOther

		if !isSpam {
			// 6. Check based on stats to which folder the email should be stored
			hs, hsErr := m.handshakeService.GetByMailioAddress(userMapping.MailioAddress, from)
			if hsErr != nil {
				if hsErr == types.ErrNotFound {
					// no handshake found, check the stats for determening the folder
					folder = m.getFolderByStats(userMapping.MailioAddress, from)
				} else {
					global.Logger.Log("error retrieving handshake", hsErr.Error())
				}
			}
			if hs != nil {
				if hs.Content.Status == types.HANDSHAKE_STATUS_ACCEPTED {
					folder = types.MailioFolderInbox
				}
				if hs.Content.Status == types.HANDSHAKE_STATUS_REVOKED {
					folder = types.MailioFolderTrash
				}
			}
		} else {
			// save to spam folder
			folder = types.MailioFolderSpam
		}

		// prepare the email for storage
		emailMarshalled, mErr := json.Marshal(email)
		if mErr != nil {
			global.Logger.Log("error marshalling email", mErr.Error())
			ApiErrorf(c, http.StatusInternalServerError, fmt.Sprintf("error marshalling email: %s", mErr.Error()))
			return
		}

		// prepare the "DIDComm" extended message for regular SMTP emails (which is not technically DIDComm, but for implementation purposes it's DIDComm)
		dcMsg := &types.DIDCommMessage{
			Type:            "application/mailio-smtp+json",
			From:            email.From.Address,
			Intent:          types.DIDCommIntentMessage,
			To:              allTo,
			ID:              email.MessageId,
			CreatedTime:     time.Now().UnixMilli(),
			PlainBodyBase64: base64.StdEncoding.EncodeToString(emailMarshalled),
		}
		uniqueID, _ := util.DIDDocumentToUniqueID(dcMsg, folder)

		mailioMessage := &types.MailioMessage{
			From:           email.From.Address,
			ID:             uniqueID,
			Folder:         folder,
			Created:        time.Now().UnixMilli(),
			IsRead:         false,
			IsForwarded:    isForwarded(email),
			IsReplied:      isReply(email),
			DIDCommMessage: dcMsg,
		}
		mm, mErr := m.userService.SaveMessage(userMapping.MailioAddress, mailioMessage)
		if mErr != nil {
			global.Logger.Log("error saving message", mErr.Error())
			ApiErrorf(c, http.StatusInternalServerError, fmt.Sprintf("error saving message: %s", mErr.Error()))
			return
		}
		global.Logger.Log("message saved", mm.ID)
	}
	c.JSON(200, gin.H{"message": "Webhook processed succesfully"})
	// 7. Check if user is subscribed user??? (in the future - effects the disk space and the folder selection)
	// 8. Make sure the incoming email is for someone with the locally registered domain
	// 8.1. Make sure multiple domains are supported (web based initial config?)
}

// sendBounce sends a bounce email to the sender of the email
func sendBounce(email *smtptypes.Mail, c *gin.Context, smtpHandler smtpmodule.SmtpHandler, code, message string) {
	bounceMail, bErr := smtpmodule.ToBounce(email.From, *email, code, message, global.Conf.Host)
	if bErr != nil {
		global.Logger.Log("error", bErr.Error())
		ApiErrorf(c, 500, fmt.Sprintf("error creating bounce email: %s", bErr.Error()))
		return
	}
	_, sndErr := smtpHandler.SendMimeMail(bounceMail, []mail.Address{email.From})
	if sndErr != nil {
		global.Logger.Log("error sending bounce email", sndErr.Error())
		ApiErrorf(c, 500, fmt.Sprintf("error sending bounce email: %s", sndErr.Error()))
	}
	c.JSON(200, gin.H{"message": "Email size is too large"})
}

func (m *MailReceiveWebhook) getFolderByStats(mailioAddress, from string) string {
	receivedAll := 0
	receivedRead := 0
	sent := 0

	toTimestamp := time.Now().UnixMilli()
	currentTime := time.UnixMilli(toTimestamp)
	sixMonthsAgo := currentTime.AddDate(0, -3, 0)
	fromTimestamp := sixMonthsAgo.UnixMilli() // 3 months ago

	countSent, csErr := m.userService.CountNumberOfSentMessages(mailioAddress, fromTimestamp, toTimestamp)
	if csErr != nil {
		global.Logger.Log("error counting number of sent messages to email", csErr.Error())
	} else {
		sent = util.SumUpItemsFromFolderCountResponse([]string{types.MailioFolderSent}, countSent)
	}
	// check if any sent message in the past 3 months (if yes, then store response in inbox)
	if sent > 0 {
		return types.MailioFolderInbox
	}

	countReceivedAll, crErr := m.userService.CountNumberOfReceivedMessages(mailioAddress, from, false, fromTimestamp, toTimestamp)
	countReceivedRead, crrErr := m.userService.CountNumberOfReceivedMessages(mailioAddress, from, true, fromTimestamp, toTimestamp)
	if errors.Join(crErr, crrErr) != nil {
		global.Logger.Log("error counting number of received messages", errors.Join(crErr, crrErr).Error())
	} else {
		receivedAll = util.SumUpItemsFromFolderCountResponse([]string{types.MailioFolderInbox, types.MailioFolderArchive, types.MailioFolderGoodReads, types.MailioFolderOther, types.MailioFolderTrash}, countReceivedAll)
		receivedRead = util.SumUpItemsFromFolderCountResponse([]string{types.MailioFolderInbox, types.MailioFolderArchive, types.MailioFolderGoodReads, types.MailioFolderOther, types.MailioFolderTrash}, countReceivedRead)
	}
	// if first time message, then store in inbox
	if receivedAll == 0 {
		return types.MailioFolderInbox
	}
	// ratio of read messages vs all received messages
	ratio := float32(receivedRead) / float32(receivedAll)
	// if more than X% of the messages are read, then store in goodreads
	ratioThreshold := float32(global.Conf.Mailio.ReadVsReceived) / 100.0
	if ratio >= ratioThreshold {
		return types.MailioFolderGoodReads
	}

	// default folder
	return types.MailioFolderOther
}

// simple determination of a forwarded email
func isForwarded(email *smtptypes.Mail) bool {
	if email.Headers != nil {
		for key, values := range email.Headers {
			if strings.EqualFold(key, "X-Forwarded-For") && len(values) > 0 {
				return true
			}
		}
	}
	return false
}

// simple determination of a reply
func isReply(email *smtptypes.Mail) bool {
	if email.Headers != nil {
		// Check for the In-Reply-To header to identify a direct reply.
		for key, values := range email.Headers {
			if strings.EqualFold(key, "In-Reply-To") && len(values) > 0 {
				return true
			}
		}
		// Optionally, check for a pattern in the subject line.
		// This is less reliable and should be used with caution.
		if subjectValues, ok := email.Headers["Subject"]; ok && len(subjectValues) > 0 {
			subject := subjectValues[0]
			if strings.HasPrefix(strings.ToLower(subject), "re:") {
				return true
			}
		}
		// Very simple analysis of the References header. (is more than 1 then it's a reply within a thread)
		if references, ok := email.Headers["References"]; ok && len(references) > 1 {
			return true
		}
	}
	return false
}
