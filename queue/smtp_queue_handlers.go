package queue

import (
	"context"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/mail"
	"net/url"
	"runtime/debug"
	"strings"
	"time"

	"github.com/hibiken/asynq"
	diskusagehandler "github.com/mailio/go-mailio-diskusage-handler"
	"github.com/mailio/go-mailio-server/diskusage"
	mailiosmtp "github.com/mailio/go-mailio-server/email/smtp"
	smtptypes "github.com/mailio/go-mailio-server/email/smtp/types"
	smtpvalidator "github.com/mailio/go-mailio-server/email/validator"
	"github.com/mailio/go-mailio-server/global"
	"github.com/mailio/go-mailio-server/services"
	"github.com/mailio/go-mailio-server/types"
	"github.com/mailio/go-mailio-server/util"
	"github.com/redis/go-redis/v9"
)

// Sending email message using SMTP
// 1. Checks if user canceled the email sending
// 2. deletes the draft message per message ID
func (msq *MessageQueue) SendSMTPMessage(fromMailioAddress string, email *types.SmtpEmailInput, taskId string) error {
	// check if the user canceled the email sending
	// if the user canceled the email sending, delete the draft message per message ID
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// check if the user canceled the email sending
	taskCanceled, tsErr := msq.env.RedisClient.Get(ctx, fmt.Sprintf("cancel:%s", taskId)).Result()
	if tsErr != nil {
		if tsErr != redis.Nil {
			global.Logger.Log(tsErr.Error(), "failed to retrieve task status", taskId)
		}
	}
	// if the user canceled the email sending, terminate function
	if taskCanceled != "" {
		_, tcdErr := msq.env.RedisClient.Del(ctx, fmt.Sprintf("cancel:%s", taskId)).Result()
		if tcdErr != nil {
			global.Logger.Log(tcdErr.Error(), "failed to delete task status", taskId)
		}
		global.Logger.Log("task canceled", "task canceled", taskId)
		return nil
	}

	securityStatus := "clean" // default
	smtpEmail, smtpConvErr := util.ConvertToSmtpEmail(*email)
	if smtpConvErr != nil {
		global.Logger.Log(smtpConvErr.Error(), "failed to convert email")
		return fmt.Errorf("failed converting email: %v: %w", smtpConvErr, asynq.SkipRetry)
	}

	// SMTP validation handler (no validators registered at this time)
	smtpValidatorHandlers := smtpvalidator.Handlers()
	if len(smtpValidatorHandlers) > 0 {
		// call each validator handler
		for _, name := range smtpValidatorHandlers {
			smtpVErr := smtpvalidator.GetHandler(name).Validate(smtpEmail)
			if smtpVErr != nil {
				global.Logger.Log(smtpVErr.Error(), "failed to validate email")
				return fmt.Errorf("failed validating email: %v: %w", smtpVErr, asynq.SkipRetry)
			}
		}
	}

	// support multiple emails domains (based on the FROM domain use the handler for instance)
	domain := strings.Split(smtpEmail.From.Address, "@")[1]
	if !util.IsSupportedSmtpDomain(domain) {
		global.Logger.Log("unsupported domain", domain)
		return fmt.Errorf("unsupported domain: %w", asynq.SkipRetry)
	}
	// finding the supported SMTP email handler from the senders email domain
	mgHandler := mailiosmtp.GetHandler(domain)
	if mgHandler == nil {
		global.Logger.Log("failed retrieving an smtp handler")
		return fmt.Errorf("failed retrieving an smtp handler: %w", asynq.SkipRetry)
	}

	// generate message ID
	rfc2822MessageID, idErr := mailiosmtp.GenerateRFC2822MessageID(domain)
	if idErr != nil {
		global.Logger.Log(idErr.Error(), "failed to generate message ID")
		return fmt.Errorf("failed generating message ID: %v: %w", idErr, asynq.SkipRetry)
	}
	// set the message ID
	smtpEmail.MessageId = rfc2822MessageID
	//TODO: check if message is reply to another message (In-Reply-To or References headers)

	// download attachments from s3 and store in the email object
	paErr := msq.processSendAttachments(smtpEmail)
	if paErr != nil {
		global.Logger.Log(paErr.Error(), "failed processing attachments")
		return fmt.Errorf("failed processing attachments: %v: %w", paErr, asynq.SkipRetry)
	}

	// convert email to mime
	mime, mErr := mailiosmtp.ToMime(smtpEmail, rfc2822MessageID)
	if mErr != nil {
		global.Logger.Log(mErr.Error(), "failed to create mime")
		return fmt.Errorf("failed converting email to mime: %v: %w", mErr, asynq.SkipRetry)
	}

	// before storing the email in the database, we need to remove the attachment contents
	// as they are stored in s3 and we only need the s3 urls
	if len(email.Attachments) > 0 {
		for i := range email.Attachments {
			email.Attachments[i].Content = []byte{}
		}
	}

	// store the email in the database
	emailBytes, ebErr := json.Marshal(email)
	if ebErr != nil {
		global.Logger.Log(ebErr.Error(), "failed to marshal email")
		return fmt.Errorf("failed marshaling email: %v: %w", ebErr, asynq.SkipRetry)
	}
	plainBody := base64.StdEncoding.EncodeToString(emailBytes)

	// store into the users database the message
	tos := []string{}
	for _, to := range smtpEmail.To {
		tos = append(tos, to.String())
	}

	// store message in the database
	mm := &types.MailioMessage{
		BaseDocument: types.BaseDocument{
			ID: rfc2822MessageID,
		},
		ID:      taskId,
		From:    smtpEmail.From.Address,
		Folder:  types.MailioFolderSent,
		Created: time.Now().UTC().UnixMilli(),
		IsRead:  true, // send messages are read by default
		DIDCommMessage: &types.DIDCommMessage{
			Type:            "application/mailio-smtp+json",
			ID:              rfc2822MessageID,
			From:            smtpEmail.From.String(),
			To:              tos,
			Thid:            rfc2822MessageID, // TODO!: check the reply fields and such
			CreatedTime:     time.Now().UTC().UnixMilli(),
			Intent:          types.SMPTIntentMessage,
			PlainBodyBase64: plainBody,
		},
		SecurityStatus: securityStatus,
	}
	_, msErr := msq.userService.SaveMessage(fromMailioAddress, mm)
	if msErr != nil {
		global.Logger.Log(msErr.Error(), "failed to save message")
		return fmt.Errorf("failed saving message: %v: %w", msErr, asynq.SkipRetry)
	}

	// process statistics on successfully sent email
	msq.statisticsService.ProcessEmailsSentStatistics(fromMailioAddress)
	for _, to := range tos {
		msq.statisticsService.ProcessEmailStatistics(fromMailioAddress, to)
	}

	//TODO: uncomment when the email sending is enabled
	fmt.Printf("sending email: %s\n", mime)
	// docID, err := mgHandler.SendMimeMail(smtpEmail.From, mime, smtpEmail.To)
	// if err != nil {
	// 	global.Logger.Log(err.Error(), "failed to send smtp email")
	// 	//TODO: store the email in the inbox folder if sending fails
	// 	return fmt.Errorf("failed sending smtp email: %v: %w", err, asynq.SkipRetry)
	// }
	// global.Logger.Log(fmt.Sprintf("smtp message sent: %s", docID), "message sent")

	// remove possible attachments to be removed (the cient reports those when only 1 type of recipient is present, but both encrypted and plain attachments is uploaded)
	for _, att := range email.DeleteAttachments {
		// delete the attachment
		global.Logger.Log("deleting attachment", att)
		parsedURL, pErr := url.Parse(att)
		if pErr != nil {
			global.Logger.Log(pErr.Error(), "failed to parse attachment url")
			continue
		}
		// Extract the file key from the path (after the first "/")
		split := strings.Split(parsedURL.Path, "/")
		fileKey := fromMailioAddress + "/" + split[len(split)-1]
		if fileKey == "" {
			global.Logger.Log("error", "invalid attachment url", "attachmentUrl", att)
			continue
		}
		fileKey = strings.ReplaceAll(fileKey, "?enc=1", "")
		dErr := msq.s3Service.DeleteAttachment(global.Conf.Storage.Bucket, fileKey)
		if dErr != nil {
			global.Logger.Log(dErr.Error(), "failed to delete attachment", att)
			continue
		}
	}

	return nil
}

// ReceiveSMTPMessage processes an incoming SMTP email message and handles it according to various rules and checks.
// The function performs the following steps:
//  1. Determines the default folder for the email.
//  2. Checks if the email is marked as spam and adjusts the folder accordingly.
//  3. Prepares the recipients list.
//  4. Iterates over each recipient to perform various checks and actions:
//     a. Retrieves the SMTP handler for the recipient's domain.
//     b. Checks if the user exists in the database.
//     c. Retrieves the user's profile and checks if the user is enabled.
//     d. Checks if the user is over the disk space limit on external disk storages.
//     e. Processes any attachments in the email.
//     f. If the email is not spam, performs additional checks using handshakes and statistics to determine the folder.
//  5. Prepares the email for storage by marshalling it into JSON.
//  6. Constructs a DIDCommMessage for compatibility with the client main JSON structure.
//  7. Saves the email message to the database.
//
// Detailed Description:
// - The default folder is initially set to `MailioFolderOther`.
// - If the email's SpamVerdict status is `VerdictStatusFail`, the email is marked as spam and the folder is set to `MailioFolderSpam`.
// - For each recipient in the email:
//   - The SMTP handler for the recipient's domain is retrieved using `mailiosmtp.GetHandler`.
//   - The recipient's email address is hashed and encoded to check for user existence in the database.
//   - The user's profile is retrieved and checked if it is enabled.
//   - The total disk usage for the user is calculated and compared against their disk space limit.
//   - Attachments in the email are processed using `processAttachments`.
//   - If the email is not marked as spam, additional checks are performed using handshakes and email statistics to determine the appropriate folder.
//
// - The email is marshalled into JSON format and a DIDCommMessage is constructed.
// - The email message is saved to the database using `userService.SaveMessage`.
// - Errors are logged using `global.Logger.Log` and appropriate bounce messages are sent using `sendBounce`.
func (msq *MessageQueue) ReceiveSMTPMessage(email *smtptypes.Mail, taskId string) error {
	// default folder
	folder := types.MailioFolderOther

	securityStatus := "clean"

	// Check if the email is market as spam (to spam folder)
	isSpam := false
	if email.SpamVerdict != nil && email.SpamVerdict.Status == smtptypes.VerdictStatusFail {
		// save to spam folder for all recipients
		isSpam = true
		folder = types.MailioFolderSpam
		securityStatus = "spam"
	}

	// prepare to fields
	allTo := []string{}
	for _, to := range email.To {
		allTo = append(allTo, to.String())
	}

	for _, to := range email.To {
		// get the smtp provider from the recipient domain
		toDomain := strings.Split(to.Address, "@")[1]
		smtpHandler := mailiosmtp.GetHandler(toDomain)
		if smtpHandler == nil {
			global.Logger.Log("failed retrieving an smtp handler")
			return fmt.Errorf("failed retrieving an smtp handler: %w", asynq.SkipRetry)
		}

		// check if user exists in the database
		scryptedMail, err := util.ScryptEmail(to.Address)
		if err != nil {
			sendBounce(to, email, smtpHandler, "4.3.0", fmt.Sprintf("Recipient not found: %s", to.Address))
			continue
		}
		userMapping, umErr := msq.userService.FindUserByScryptEmail(scryptedMail)
		if umErr != nil {
			if umErr == types.ErrNotFound {
				global.Logger.Log("error, find user by scrypt not found", to.Address, umErr.Error())
				sendBounce(to, email, smtpHandler, "4.3.0", fmt.Sprintf("Recipient not found: %s", to.Address))
				continue
			}
		}

		// retrieve users profile
		userProfile, upErr := msq.userProfileService.Get(userMapping.MailioAddress)
		if upErr != nil {
			global.Logger.Log("error", upErr.Error())
			sendBounce(to, email, smtpHandler, "4.3.0", fmt.Sprintf("Recipient not found: %s", to.Address))
			continue
		}
		if !userProfile.Enabled {
			global.Logger.Log("user disabled", userMapping.MailioAddress)
			sendBounce(to, email, smtpHandler, "5.1.1", "Mailbox unavailable")
			continue
		}

		// check if user is over disk space limit on external disk storages
		totalDiskUsageFromHandlers := int64(0)
		for _, diskUsageHandler := range diskusage.Handlers() {
			awsDiskUsage, awsDuErr := diskusage.GetHandler(diskUsageHandler).GetDiskUsage(userMapping.MailioAddress)
			if awsDuErr != nil {
				if awsDuErr != diskusagehandler.ErrNotFound {
					global.Logger.Log("error retrieving disk usage stats", awsDuErr.Error())
				}
			}
			if awsDiskUsage != nil {
				totalDiskUsageFromHandlers += awsDiskUsage.SizeBytes
			}
		}

		stats, sErr := msq.userProfileService.Stats(userMapping.MailioAddress)
		if sErr != nil {
			global.Logger.Log("error retrieving disk usage stats", sErr.Error())
		}
		totalDiskUsage := stats.ActiveSize + totalDiskUsageFromHandlers
		if totalDiskUsage > userProfile.DiskSpace {
			sendBounce(to, email, smtpHandler, "5.2.2", "Over disk space limit")
			continue
		}

		// uploads attachments to s3 and stores references in the email object
		paErr := msq.processReceiveAttachments(email, userMapping.MailioAddress)
		if paErr != nil {
			if paErr == types.ErrMessageTooLarge {
				global.Logger.Log("attachment too large", "messageId", email.MessageId)
				sendBounce(to, email, smtpHandler, "5.3.4", "Message too large")
				continue
			}
			if paErr.Error() == "malware detected" {
				global.Logger.Log("malware detected", "messageId", email.MessageId)
				sendBounce(to, email, smtpHandler, "5.6.1", "Malware detected")
				isSpam = true
				securityStatus = "malware"
			}
			global.Logger.Log("error processing attachments", paErr.Error())
			sendBounce(to, email, smtpHandler, "4.5.1", "Local error in processing")
			continue
		}

		// only do the following if the incoming email is not marked as spam
		if !isSpam {
			// get user handshake if exists
			handshake, hErr := services.GetHandshakeByID(msq.userRepo, userMapping.MailioAddress, to.Address)
			if hErr != nil {
				if hErr != types.ErrNotFound {
					global.Logger.Log("error finding handshake to ", to.Address, userMapping.MailioAddress, hErr.Error())
					// ignore the error
				}
			}
			if handshake != nil {
				if handshake.Content.Status == types.HANDSHAKE_STATUS_REVOKED {
					folder = types.MailioFolderTrash
				} else if handshake.Content.Status == types.HANDSHAKE_STATUS_ACCEPTED {
					folder = types.MailioFolderInbox
				}
			} else {
				// if handshake hasn't deemed the email to be in the inbox, then check statistics
				f, fErr := msq.selectMailFolder(email.From.Address, userMapping.MailioAddress)
				if fErr != nil {
					global.Logger.Log("error selecting mail folder", fErr.Error())
					folder = types.MailioFolderInbox // default to inbox
				} else {
					folder = f
				}
			}
		}

		// prepare the parsed email to be stored in database
		emailMarshalled, mErr := json.Marshal(email)
		if mErr != nil {
			global.Logger.Log("error marshalling email", mErr.Error())
			return nil
		}
		// prepare the "DIDComm" extended message for regular SMTP emails (which is not technically DIDComm, only for client main json structure compatibility)
		dcMsg := &types.DIDCommMessage{
			Type:            "application/mailio-smtp+json",
			From:            email.From.Address,
			Intent:          types.DIDCommIntentMessage,
			To:              allTo,
			ID:              email.MessageId,
			CreatedTime:     time.Now().UnixMilli(),
			PlainBodyBase64: base64.StdEncoding.EncodeToString(emailMarshalled),
		}

		mailioMessage := &types.MailioMessage{
			From:           email.From.Address,
			ID:             taskId,
			Folder:         folder,
			Created:        time.Now().UnixMilli(),
			IsRead:         false,
			IsForwarded:    isForwarded(email),
			IsReplied:      isReply(email),
			DIDCommMessage: dcMsg,
			SecurityStatus: securityStatus,
		}
		mm, mErr := msq.userService.SaveMessage(userMapping.MailioAddress, mailioMessage)
		if mErr != nil {
			global.Logger.Log("error saving message", mErr.Error())
			return mErr
		}
		global.Logger.Log("message saved", mm.ID)

		// process received email statistics
		msq.statisticsService.ProcessEmailStatistics(userMapping.MailioAddress, email.From.Address)
	}

	return nil
}

// sendBounce sends a bounce email to the sender of the original email.
//
// Parameters:
//   - bounceFromEmail: The email address from which the bounce email will be sent.
//   - email: A pointer to the original smtptypes.Mail object that triggered the bounce.
//   - smtpHandler: The SmtpHandler object used to send the bounce email.
//   - code: The SMTP status code to include in the bounce email.
//   - message: The message to include in the bounce email.
func sendBounce(bounceFromEmail mail.Address, email *smtptypes.Mail, smtpHandler mailiosmtp.SmtpHandler, code, message string) error {
	bounceMail, bErr := mailiosmtp.ToBounce(email.From, *email, code, message, global.Conf.Mailio.ServerDomain)
	if bErr != nil {
		global.Logger.Log("error", bErr.Error())
		return bErr
	}
	_, sndErr := smtpHandler.SendMimeMail(bounceFromEmail, bounceMail, []mail.Address{email.From})
	if sndErr != nil {
		global.Logger.Log("error sending bounce email", sndErr.Error())
		return sndErr
	}
	return nil
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

// processReceiveAttachments processes the attachments of the given received email.
// It generates a unique ID for each attachment, downloads the attachment
// and updates the attachment content prepared for sending.
// It also clears the content of the attachment after uploading.
//
// Parameters:
//
//		email - A pointer to the Mail object containing the email and its attachments.
//	 recipientAddress - A string representing the recipient's email address for constructing the attachment path.
//
// Errors:
//
//	types.ErrMessageTooLarge - If an attachment is larger than 30MB, the function returns an error.
func (msq *MessageQueue) processReceiveAttachments(email *smtptypes.Mail, recipientAddress string) error {
	if len(email.Attachments) > 0 {
		uploadedAttachments := make([]*smtptypes.SmtpAttachment, 0)
		for _, att := range email.Attachments {
			if att.Content == nil {
				global.Logger.Log("attachment content is nil", att.ContentID, "filename:", att.Filename, "messageId", email.MessageId)
				continue
			}
			if att.Content != nil {

				if len(att.Content) > 30*1024*1024 {
					global.Logger.Log("attachment content is too large", att.ContentID, "filename:", att.Filename, "messageId", email.MessageId, "size: ", len(att.Content))
					// deny attachments larger than 30MB
					return types.ErrMessageTooLarge
				}
				uploadedAttachment := &smtptypes.SmtpAttachment{
					ContentType: att.ContentType,
					ContentID:   att.ContentID,
					Filename:    att.Filename,
				}

				if att.Filename == "" {
					uploadedAttachment.Filename = "unknown"
				}

				if util.DetectInlineContentType(att.Filename) {
					uploadedAttachment.ContentDisposition = fmt.Sprintf(`inline; filename="%s"`, att.Filename)
				} else {
					uploadedAttachment.ContentDisposition = fmt.Sprintf(`attachment; filename="%s"`, att.Filename)
				}

				m5 := md5.New()
				m5.Write(att.Content)
				m5Sum := m5.Sum(nil)
				now := time.Now().UTC().Format("20061010t150405")
				fileMd5 := hex.EncodeToString(m5Sum)
				// check for malware of the attachment
				if msq.malwareService.IsMalware(fileMd5) {
					// TODO: store email but with warning of malware?
					global.Logger.Log("malware detected", "filename", att.Filename, "md5", fileMd5)
					return fmt.Errorf("malware detected: %w", asynq.SkipRetry)
				}
				path := recipientAddress + "/" + fileMd5 + "_" + now
				p, err := msq.s3Service.UploadAttachment(global.Conf.Storage.Bucket, path, att.Content, att.ContentType)
				if err != nil {
					fmt.Printf("Error uploading to S3: %v\n", err)
					debug.PrintStack()
					global.Logger.Log(err.Error(), "failed to upload attachment", path)
					return fmt.Errorf("failed uploading attachment: %v", err)
				}
				uploadedAttachment.ContentURL = &p
				uploadedAttachments = append(uploadedAttachments, uploadedAttachment)
			}
		}
		email.Attachments = uploadedAttachments
	}
	return nil
}

// processAttachments processes the attachments of the given email.
// It generates a unique ID for each attachment, downloads the attachment
// and updates the attachment content prepared for sending.
// It also clears the content of the attachment after uploading.
//
// Parameters:
//
//	email - A pointer to the Mail object containing the email and its attachments.
//	mailioAddress - A string representing the mailio address for constructing the attachment path.
func (msq *MessageQueue) processSendAttachments(email *smtptypes.Mail) error {
	var newAttachments []*smtptypes.SmtpAttachment
	if len(email.Attachments) > 0 {
		for _, att := range email.Attachments {
			if att.ContentURL == nil {
				continue
			}
			var newAtt smtptypes.SmtpAttachment
			dcErr := util.DeepCopy(att, &newAtt)
			if dcErr != nil {
				global.Logger.Log(dcErr.Error(), "failed to copy attachment")
				return fmt.Errorf("failed copying attachment: %v: %w", dcErr, asynq.SkipRetry)
			}
			content, dErr := msq.s3Service.DownloadAttachment(*att.ContentURL)
			if dErr != nil {
				global.Logger.Log(dErr.Error(), "failed to download attachment")
				return fmt.Errorf("failed downloading attachment: %v: %w", dErr, asynq.SkipRetry)
			}
			newAtt.Content = content
		}
	}
	email.Attachments = newAttachments
	return nil
}
