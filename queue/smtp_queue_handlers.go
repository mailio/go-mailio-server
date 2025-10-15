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
	"strings"
	"time"

	"github.com/go-kit/log/level"
	"github.com/hibiken/asynq"
	smtp "github.com/mailio/go-mailio-server/email"
	smtpvalidator "github.com/mailio/go-mailio-server/email/validator"
	"github.com/mailio/go-mailio-server/global"
	"github.com/mailio/go-mailio-server/services"
	"github.com/mailio/go-mailio-server/types"
	"github.com/mailio/go-mailio-server/util"
	abi "github.com/mailio/go-mailio-smtp-abi"
	helpers "github.com/mailio/go-mailio-smtp-helpers"
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
			level.Error(global.Logger).Log("msg", "failed to retrieve task status", "taskId", taskId, "error", tsErr)
		}
	}
	// if the user canceled the email sending, terminate function
	if taskCanceled != "" {
		_, tcdErr := msq.env.RedisClient.Del(ctx, fmt.Sprintf("cancel:%s", taskId)).Result()
		if tcdErr != nil {
			level.Error(global.Logger).Log("msg", "failed to delete task status", "taskId", taskId, "error", tcdErr)
		}
		level.Info(global.Logger).Log("msg", "task canceled", "taskId", taskId)
		return nil
	}

	securityStatus := "clean" // default

	// check if sending smtp domain supported and extract smtp sending domain
	// parse users from address
	from, fromErr := mail.ParseAddress(email.From)
	if fromErr != nil {
		level.Error(global.Logger).Log("msg", "failed to parse email address", "from", email.From)
		return fmt.Errorf("failed parsing email address: %v: %w", fromErr, asynq.SkipRetry)
	}
	domain := strings.Split(from.Address, "@")[1]
	sendingDomain, sndErr := util.ExtractSmtpSendingDomain(domain)
	if sndErr != nil {
		level.Error(global.Logger).Log("msg", "failed to extract sending domain", "from", email.From)
		return fmt.Errorf("failed extracting sending domain: %v: %w", sndErr, asynq.SkipRetry)
	}
	if sendingDomain != domain {
		level.Error(global.Logger).Log("msg", "sending domain is different from the domain in the from address", "sendingDomain", sendingDomain, "fromDomain", domain)
		return fmt.Errorf("sending domain is different from the domain in the from address: %w", asynq.SkipRetry)
	}
	email.From = from.Address

	// include the senders name if in profile and user allows it
	up, upErr := msq.userProfileService.Get(fromMailioAddress)
	if upErr != nil {
		level.Error(global.Logger).Log("msg", "failed to get user profile", "error", upErr)
	} else {
		if strings.Contains(up.WhatToShare, "displayName") {
			email.From = fmt.Sprintf("%q <%s>", up.DisplayName, from.Address)
		}
	}

	smtpEmail, smtpConvErr := util.ConvertToSmtpEmail(*email)
	if smtpConvErr != nil {
		level.Error(global.Logger).Log("msg", "failed to convert email", "error", smtpConvErr)
		return fmt.Errorf("failed converting email: %v: %w", smtpConvErr, asynq.SkipRetry)
	}

	// SMTP validation handler (no validators registered at this time)
	smtpValidatorHandlers := smtpvalidator.Handlers()
	if len(smtpValidatorHandlers) > 0 {
		// call each validator handler
		for _, name := range smtpValidatorHandlers {
			smtpVErr := smtpvalidator.GetHandler(name).Validate(smtpEmail)
			if smtpVErr != nil {
				level.Error(global.Logger).Log("msg", "failed to validate email", "error", smtpVErr)
				return fmt.Errorf("failed validating email: %v: %w", smtpVErr, asynq.SkipRetry)
			}
		}
	}

	// finding the supported SMTP email handler from the senders email domain
	mgHandler := smtp.GetHandler(sendingDomain)
	if mgHandler == nil {
		level.Error(global.Logger).Log("msg", "failed retrieving an smtp handler")
		return fmt.Errorf("failed retrieving an smtp handler: %w", asynq.SkipRetry)
	}

	// generate message ID
	rfc2822MessageID, idErr := helpers.GenerateRFC2822MessageID(domain)
	if idErr != nil {
		level.Error(global.Logger).Log("msg", "failed to generate message ID", "error", idErr)
		return fmt.Errorf("failed generating message ID: %v: %w", idErr, asynq.SkipRetry)
	}
	// set the message ID
	smtpEmail.MessageId = rfc2822MessageID
	//TODO: check if message is reply to another message (In-Reply-To or References headers)

	// download attachments from s3 and store in the email object
	paErr := msq.processSendAttachments(smtpEmail)
	if paErr != nil {
		level.Error(global.Logger).Log("msg", "failed processing attachments", "error", paErr)
		return fmt.Errorf("failed processing attachments: %v: %w", paErr, asynq.SkipRetry)
	}

	// convert email to mime
	mime, mErr := helpers.ToMime(smtpEmail, rfc2822MessageID)
	if mErr != nil {
		level.Error(global.Logger).Log("msg", "failed to create mime", "error", mErr)
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
		level.Error(global.Logger).Log("msg", "failed to marshal email", "error", ebErr)
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
		level.Error(global.Logger).Log("msg", "failed to save message", "error", msErr)
		return fmt.Errorf("failed saving message: %v: %w", msErr, asynq.SkipRetry)
	}

	// process statistics on successfully sent email
	// for statistics always full web did is used
	localUsersWebDID := "did:web:" + global.Conf.Mailio.ServerDomain + "#" + fromMailioAddress
	msq.statisticsService.ProcessEmailsSentStatistics(localUsersWebDID)
	for _, to := range tos {
		pTo, pErr := mail.ParseAddress(to)
		if pErr != nil {
			level.Error(global.Logger).Log("msg", "failed to parse email address", "error", pErr)
			continue
		}
		msq.statisticsService.ProcessEmailStatistics(localUsersWebDID, pTo.Address)
	}

	// using the handler to send the email
	// when dealing with BCC recipients, don't add them to the mime document, but add all recipients (to, cc, anc bcc to allTos)
	allTos := []mail.Address{}
	allTos = append(allTos, smtpEmail.To...)
	for _, cc := range smtpEmail.Cc {
		allTos = append(allTos, *cc)
	}
	for _, bcc := range smtpEmail.Bcc {
		allTos = append(allTos, *bcc)
	}
	docID, err := mgHandler.SendMimeMail(smtpEmail.From, mime, allTos)
	if err != nil {
		level.Error(global.Logger).Log(err.Error(), "failed to send smtp email")
		//TODO: store the email in the inbox folder if sending fails
		return fmt.Errorf("failed sending smtp email: %v: %w", err, asynq.SkipRetry)
	}
	level.Info(global.Logger).Log(fmt.Sprintf("smtp message sent: %s", docID), "message sent")

	// remove possible attachments to be removed (the cient reports those when only 1 type of recipient is present, but both encrypted and plain attachments is uploaded)
	for _, att := range email.DeleteAttachments {
		// delete the attachment
		level.Info(global.Logger).Log("deleting attachment", att)
		parsedURL, pErr := url.Parse(att)
		if pErr != nil {
			level.Error(global.Logger).Log(pErr.Error(), "failed to parse attachment url")
			continue
		}
		// Extract the file key from the path (after the first "/")
		split := strings.Split(parsedURL.Path, "/")
		fileKey := fromMailioAddress + "/" + split[len(split)-1]
		if fileKey == "" {
			level.Error(global.Logger).Log("error", "invalid attachment url", "attachmentUrl", att)
			continue
		}
		fileKey = strings.ReplaceAll(fileKey, "?enc=1", "")
		dErr := msq.s3Service.DeleteAttachment(global.Conf.Storage.Bucket, fileKey)
		if dErr != nil {
			level.Error(global.Logger).Log(dErr.Error(), "failed to delete attachment", att)
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
func (msq *MessageQueue) ReceiveSMTPMessage(email *abi.Mail, taskId string) error {
	// default folder
	folder := types.MailioFolderOther

	securityStatus := "clean"

	// Check if the email is market as spam (to spam folder)
	isSpam := false
	if email.SpamVerdict != nil && email.SpamVerdict.Status == abi.VerdictStatusFail {
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
		smtpHandler := smtp.GetHandler(toDomain)
		if smtpHandler == nil {
			level.Error(global.Logger).Log("msg", "failed retrieving an smtp handler")
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
				level.Error(global.Logger).Log("error", "find user by scrypt not found", to.Address, umErr)
				sendBounce(to, email, smtpHandler, "4.3.0", fmt.Sprintf("Recipient not found: %s", to.Address))
				continue
			}
		}

		// retrieve users profile
		userProfile, upErr := msq.userProfileService.Get(userMapping.MailioAddress)
		if upErr != nil {
			level.Error(global.Logger).Log("error", "failed to get user profile", to.Address, upErr)
			sendBounce(to, email, smtpHandler, "4.3.0", fmt.Sprintf("Recipient not found: %s", to.Address))
			continue
		}
		if !userProfile.Enabled {
			level.Error(global.Logger).Log("user disabled", userMapping.MailioAddress)
			sendBounce(to, email, smtpHandler, "5.1.1", "Mailbox unavailable")
			continue
		}

		// check if user is over disk space limit on external disk storages
		totalDiskUsageFromHandlers := util.GetDiskUsageFromDiskHandlers(userMapping.MailioAddress)

		stats, sErr := msq.userProfileService.Stats(userMapping.MailioAddress)
		if sErr != nil {
			level.Error(global.Logger).Log("retrieving disk usage stats", sErr)
		}
		totalDiskUsage := stats.ActiveSize + totalDiskUsageFromHandlers
		if totalDiskUsage >= global.Conf.Mailio.DiskSpace {
			sendBounce(to, email, smtpHandler, "5.2.2", "mailbox full")
			continue
		}

		// uploads attachments to s3 and stores references in the email object
		paErr := msq.processReceiveAttachments(email, userMapping.MailioAddress)
		if paErr != nil {
			if paErr == types.ErrMessageTooLarge {
				level.Warn(global.Logger).Log("error", "attachment too large", "messageId", email.MessageId)
				sendBounce(to, email, smtpHandler, "5.3.4", "Message too large")
				continue
			}
			if paErr.Error() == "malware detected" {
				level.Warn(global.Logger).Log("error", "malware detected", "messageId", email.MessageId)
				sendBounce(to, email, smtpHandler, "5.6.1", "Malware detected")
				isSpam = true
				securityStatus = "malware"
			}
			level.Error(global.Logger).Log("error processing attachments", paErr.Error())
			sendBounce(to, email, smtpHandler, "4.5.1", "Local error in processing")
			continue
		}

		// only do the following if the incoming email is not marked as spam
		if !isSpam {
			// get user handshake if exists
			handshake, hErr := services.GetHandshakeByID(msq.userRepo, userMapping.MailioAddress, to.Address)
			if hErr != nil {
				if hErr != types.ErrNotFound {
					level.Info(global.Logger).Log("error finding handshake to ", to.Address, userMapping.MailioAddress)
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
					level.Error(global.Logger).Log("error selecting mail folder", fErr.Error())
					folder = types.MailioFolderInbox // default to inbox
				} else {
					folder = f
				}
			}
		}

		// prepare the parsed email to be stored in database
		emailMarshalled, mErr := json.Marshal(email)
		if mErr != nil {
			level.Error(global.Logger).Log("error marshalling email", mErr.Error())
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
			level.Error(global.Logger).Log("error saving message", mErr.Error())
			return mErr
		}
		level.Info(global.Logger).Log("message saved", mm.ID)

		// process received email statistics (for local recipient always use full web did for statistics)
		localUsersWebDID := "did:web:" + global.Conf.Mailio.ServerDomain + "#" + userMapping.MailioAddress
		msq.statisticsService.ProcessEmailStatistics(email.From.Address, localUsersWebDID)
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
func sendBounce(bounceFromEmail mail.Address, email *abi.Mail, smtpHandler abi.SmtpHandler, code, message string) error {
	bounceMail, bErr := helpers.ToBounce(email.From, *email, code, message, global.Conf.Mailio.ServerDomain)
	if bErr != nil {
		level.Error(global.Logger).Log("bounce preparation", bErr.Error())
		return bErr
	}
	_, sndErr := smtpHandler.SendMimeMail(bounceFromEmail, bounceMail, []mail.Address{email.From})
	if sndErr != nil {
		level.Error(global.Logger).Log("error sending bounce email", sndErr.Error())
		return sndErr
	}
	return nil
}

// simple determination of a forwarded email
func isForwarded(email *abi.Mail) bool {
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
func isReply(email *abi.Mail) bool {
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
func (msq *MessageQueue) processReceiveAttachments(email *abi.Mail, recipientAddress string) error {
	var totalSize int64 = 0
	const maxTotalSize int64 = 30 * 1024 * 1024 // 30MB in bytes

	if len(email.Attachments) > 0 {
		// validate the size of the attachments (total size and each attachment size)
		for _, att := range email.Attachments {
			if len(att.Content) > int(maxTotalSize) {
				level.Warn(global.Logger).Log("attachment content is too large", att.ContentID, "filename:", att.Filename, "messageId", email.MessageId, "size: ", len(att.Content))
				// deny attachments larger than 30MB
				return types.ErrMessageTooLarge
			}
			totalSize += int64(len(att.Content))
		}
		if totalSize > maxTotalSize {
			// total size of all attachments exceeds limit
			level.Error(global.Logger).Log("total attachment size exceeds limit", "totalSize", totalSize, "maxSize", maxTotalSize)
			return types.ErrMessageTooLarge
		}
		// if validation passes, upload the attachments
		uploadedAttachments := make([]*abi.SmtpAttachment, 0)
		for _, att := range email.Attachments {
			if att.Content == nil {
				level.Error(global.Logger).Log("attachment content is nil", att.ContentID, "filename:", att.Filename, "messageId", email.MessageId)
				continue
			}
			if att.Content != nil {
				uploadedAttachment := &abi.SmtpAttachment{
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
					level.Error(global.Logger).Log("malware detected", "filename", att.Filename, "md5", fileMd5)
					return fmt.Errorf("malware detected: %w", asynq.SkipRetry)
				}
				path := recipientAddress + "/" + fileMd5 + "_" + now
				p, err := msq.s3Service.UploadAttachment(global.Conf.Storage.Bucket, path, att.Content, att.ContentType)
				if err != nil {
					level.Error(global.Logger).Log(err.Error(), "failed to upload attachment", path)
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
func (msq *MessageQueue) processSendAttachments(email *abi.Mail) error {
	var newAttachments []*abi.SmtpAttachment
	if len(email.Attachments) > 0 {
		for _, att := range email.Attachments {
			if att.ContentURL == nil {
				continue
			}
			var newAtt abi.SmtpAttachment
			dcErr := util.DeepCopy(att, &newAtt)
			if dcErr != nil {
				level.Error(global.Logger).Log(dcErr.Error(), "failed to copy attachment")
				return fmt.Errorf("failed copying attachment: %v: %w", dcErr, asynq.SkipRetry)
			}
			content, dErr := msq.s3Service.DownloadAttachment(*att.ContentURL)
			if dErr != nil {
				level.Error(global.Logger).Log(dErr.Error(), "failed to download attachment")
				return fmt.Errorf("failed downloading attachment: %v: %w", dErr, asynq.SkipRetry)
			}
			newAtt.Content = content
			newAttachments = append(newAttachments, &newAtt)
		}
	}
	email.Attachments = newAttachments
	return nil
}
