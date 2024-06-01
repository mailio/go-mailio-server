package queue

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/mail"
	"strings"
	"time"

	"github.com/hibiken/asynq"
	diskusagehandler "github.com/mailio/go-mailio-diskusage-handler"
	"github.com/mailio/go-mailio-server/diskusage"
	mailiosmtp "github.com/mailio/go-mailio-server/email/smtp"
	smtptypes "github.com/mailio/go-mailio-server/email/smtp/types"
	"github.com/mailio/go-mailio-server/global"
	"github.com/mailio/go-mailio-server/types"
	"github.com/mailio/go-mailio-server/util"
	"github.com/redis/go-redis/v9"
)

// Sending email message using SMTP
// 1. Checks if user canceled the email sending
// 2. deletes the draft message per message ID
func (msq *MessageQueue) SendSMTPMessage(fromMailioAddress string, email *smtptypes.Mail, taskId string) error {
	// check if the user canceled the email sending
	// if the user canceled the email sending, delete the draft message per message ID
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	taskCanceled, tsErr := msq.env.RedisClient.Get(ctx, fmt.Sprintf("cancel:%s", taskId)).Result()
	if tsErr != nil {
		if tsErr != redis.Nil {
			global.Logger.Log(tsErr.Error(), "failed to retrieve task status", taskId)
		}
	}
	if taskCanceled != "" {
		_, tcdErr := msq.env.RedisClient.Del(ctx, fmt.Sprintf("cancel:%s", taskId)).Result()
		if tcdErr != nil {
			global.Logger.Log(tcdErr.Error(), "failed to delete task status", taskId)
		}
		global.Logger.Log("task canceled", "task canceled", taskId)
		return nil
	}

	// get the registered handler (only mailgun for now, but later based on "from" domain)
	//TODO!: support multiple domains (based on the FROM domain use the handler for instance)
	mgHandler := mailiosmtp.GetHandler("mailgun")
	if mgHandler == nil {
		global.Logger.Log("failed retrieving an smtp handler")
		return fmt.Errorf("failed retrieving an smtp handler: %w", asynq.SkipRetry)
	}

	// generate message ID
	rfc2822MessageID, idErr := mailiosmtp.GenerateRFC2822MessageID(global.Conf.Mailio.Domain)
	if idErr != nil {
		global.Logger.Log(idErr.Error(), "failed to generate message ID")
		return fmt.Errorf("failed generating message ID: %v: %w", idErr, asynq.SkipRetry)
	}
	// set the message ID
	email.MessageId = rfc2822MessageID
	//TODO: check if message is reply to another message (In-Reply-To or References headers)

	// convert email to mime
	mime, mErr := mailiosmtp.ToMime(email, rfc2822MessageID)
	if mErr != nil {
		global.Logger.Log(mErr.Error(), "failed to create mime")
		return fmt.Errorf("failed converting email to mime: %v: %w", mErr, asynq.SkipRetry)
	}

	paErr := msq.processAttachments(email, fromMailioAddress)
	if paErr != nil {
		global.Logger.Log(paErr.Error(), "failed processing attachments")
		return fmt.Errorf("failed processing attachments: %v: %w", paErr, asynq.SkipRetry)
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
	for _, to := range email.To {
		tos = append(tos, to.String())
	}

	// store message in the database
	mm := &types.MailioMessage{
		BaseDocument: types.BaseDocument{
			ID: rfc2822MessageID,
		},
		ID:      taskId,
		From:    email.From.Address,
		Folder:  types.MailioFolderSent,
		Created: time.Now().UTC().UnixMilli(),
		IsRead:  true, // send messages are read by default
		DIDCommMessage: &types.DIDCommMessage{
			Type:            "application/mailio-smtp+json",
			ID:              rfc2822MessageID,
			From:            email.From.String(),
			To:              tos,
			Thid:            rfc2822MessageID, // TODO!: check the reply fields and such
			CreatedTime:     time.Now().UTC().UnixMilli(),
			Intent:          types.SMPTIntentMessage,
			PlainBodyBase64: plainBody,
		},
	}
	_, msErr := msq.userService.SaveMessage(fromMailioAddress, mm)
	if msErr != nil {
		global.Logger.Log(msErr.Error(), "failed to save message")
		return fmt.Errorf("failed saving message: %v: %w", msErr, asynq.SkipRetry)
	}

	docID, err := mgHandler.SendMimeMail(mime, email.To)
	if err != nil {
		global.Logger.Log(err.Error(), "failed to send smtp email")
		return fmt.Errorf("failed sending smtp email: %v: %w", err, asynq.SkipRetry)
	}
	global.Logger.Log(fmt.Sprintf("smtp message sent: %s", docID), "message sent")

	return nil
}

// process received email message using SMTP
func (msq *MessageQueue) ReceiveSMTPMessage(email *smtptypes.Mail, taskId string, smtpProvider string) error {

	//TODO! Check if user is subscribed user??? (in the future - effects the disk space and the folder selection)
	//TODO! Make sure the incoming email is for someone with the locally registered domain
	//TODO! Make sure multiple domains are supported (web based initial config?)

	// get the smtp provider from register
	smtpHandler := mailiosmtp.GetHandler(smtpProvider)
	if smtpHandler == nil {
		global.Logger.Log("failed retrieving an smtp handler")
		return fmt.Errorf("failed retrieving an smtp handler: %w", asynq.SkipRetry)
	}

	// default folder
	folder := types.MailioFolderOther

	// Check if the email is market as spam (to spam folder)
	isSpam := false
	if email.SpamVerdict != nil && email.SpamVerdict.Status == smtptypes.VerdictStatusFail {
		// save to spam folder for all recipients
		isSpam = true
		folder = types.MailioFolderSpam
	}

	// prepare to fields
	allTo := []string{}
	for _, to := range email.To {
		allTo = append(allTo, to.String())
	}

	for _, to := range email.To {
		// check if user exists in the database
		scryptedMail, err := util.ScryptEmail(to.Address)
		if err != nil {
			sendBounce(email, smtpHandler, "4.3.0", fmt.Sprintf("Recipient not found: %s", to.Address))
		}
		scryptedBaseUrl64 := base64.URLEncoding.EncodeToString(scryptedMail)
		userMapping, umErr := msq.userService.FindUserByScryptEmail(scryptedBaseUrl64)
		if umErr != nil {
			if umErr == types.ErrNotFound {
				global.Logger.Log("error, find user by scrypt not found", to.Address, umErr.Error())
				sendBounce(email, smtpHandler, "4.3.0", fmt.Sprintf("Recipient not found: %s", to.Address))
				continue
			}
		}

		// retrieve users profile
		userProfile, upErr := msq.userProfileService.Get(userMapping.MailioAddress)
		if upErr != nil {
			global.Logger.Log("error", upErr.Error())
			sendBounce(email, smtpHandler, "4.3.0", fmt.Sprintf("Recipient not found: %s", to.Address))
		}
		if !userProfile.Enabled {
			global.Logger.Log("user disabled", userMapping.MailioAddress)
			sendBounce(email, smtpHandler, "5.1.1", "Mailbox unavailable")
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
			sendBounce(email, smtpHandler, "5.2.2", "Over disk space limit")
			continue
		}

		paErr := msq.processAttachments(email, userMapping.MailioAddress)
		if paErr != nil {
			global.Logger.Log("error processing attachments", paErr.Error())
			sendBounce(email, smtpHandler, "5.3.4", "Error processing attachments")
			continue
		}

		// only do the following if the incoming email is not marked as spam
		if !isSpam {
			// get user handshake if exists
			handshake, hErr := msq.handshakeService.GetByMailioAddress(userMapping.MailioAddress, to.Address)
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
				folder = msq.getFolderByStats(userMapping.MailioAddress, email.From.Address)
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
		}
		mm, mErr := msq.userService.SaveMessage(userMapping.MailioAddress, mailioMessage)
		if mErr != nil {
			global.Logger.Log("error saving message", mErr.Error())
			return mErr
		}
		global.Logger.Log("message saved", mm.ID)
	}

	return nil
}

func sendBounce(email *smtptypes.Mail, smtpHandler mailiosmtp.SmtpHandler, code, message string) error {
	bounceMail, bErr := mailiosmtp.ToBounce(email.From, *email, code, message, global.Conf.Host)
	if bErr != nil {
		global.Logger.Log("error", bErr.Error())
		return bErr
	}
	_, sndErr := smtpHandler.SendMimeMail(bounceMail, []mail.Address{email.From})
	if sndErr != nil {
		global.Logger.Log("error sending bounce email", sndErr.Error())
		return sndErr
	}
	return nil
}

func (msq *MessageQueue) getFolderByStats(mailioAddress, from string) string {
	receivedAll := 0
	receivedRead := 0
	sent := 0

	toTimestamp := time.Now().UnixMilli()
	currentTime := time.UnixMilli(toTimestamp)
	sixMonthsAgo := currentTime.AddDate(0, -3, 0)
	fromTimestamp := sixMonthsAgo.UnixMilli() // 3 months ago

	// count the number of sent messages to the recipient email or Mailio address
	countSent, csErr := msq.userService.CountNumberOfSentByRecipientMessages(mailioAddress, from, fromTimestamp, toTimestamp)
	if csErr != nil {
		global.Logger.Log("error counting number of sent messages to email", csErr.Error())
	} else {
		if len(countSent.Rows) > 0 {
			sent = countSent.Rows[0].Value
		}
	}
	// check if any sent message in the past 3 months (if yes, then store response in inbox)
	if sent > 0 {
		return types.MailioFolderInbox
	}

	countReceivedAll, crErr := msq.userService.CountNumberOfMessages(mailioAddress, from, "", false, fromTimestamp, toTimestamp)
	countReceivedRead, crrErr := msq.userService.CountNumberOfMessages(mailioAddress, from, "", true, fromTimestamp, toTimestamp)
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

// processAttachments processes the attachments of the given email.
// It generates a unique ID for each attachment, uploads the attachment
// to the specified storage bucket, and updates the attachment's ContentURL.
// It also clears the content of the attachment after uploading.
//
// Parameters:
//
//	email - A pointer to the Mail object containing the email and its attachments.
//	mailioAddress - A string representing the mailio address for constructing the attachment path.
func (msq *MessageQueue) processAttachments(email *smtptypes.Mail, mailioAddress string) error {
	if len(email.Attachments) > 0 {
		for i := range email.Attachments {
			attachmentID, aErr := util.SmtpMailToUniqueID(email, email.Attachments[i].Filename)
			if aErr != nil {
				global.Logger.Log(aErr.Error(), "failed to create attachment ID")
			}
			attPath := fmt.Sprintf("/%s/%s", mailioAddress, attachmentID)
			url, s3Err := msq.userService.UploadAttachment(global.Conf.Storage.Bucket, attPath, email.Attachments[i].Content)
			if s3Err != nil {
				global.Logger.Log(s3Err.Error(), "failed to upload attachment")
				return fmt.Errorf("failed uploading attachment: %v: %w", s3Err, asynq.SkipRetry)
			}
			email.Attachments[i].ContentURL = &url
			email.Attachments[i].Content = []byte{} // clear the content
		}
	}
	return nil
}
