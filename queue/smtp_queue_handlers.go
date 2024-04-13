package queue

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/hibiken/asynq"
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

	// strip out and upload attachments to s3
	if len(email.Attachments) > 0 {
		for _, attachment := range email.Attachments {
			attachmentID, aErr := util.SmtpMailToUniqueID(email, attachment.Filename)
			if aErr != nil {
				global.Logger.Log(aErr.Error(), "failed to create attachment ID")
			}
			attPath := fmt.Sprintf("/%s/%s", fromMailioAddress, attachmentID)
			_, s3Err := msq.userService.UploadAttachment(global.Conf.Storage.Bucket, attPath, attachment.Content)
			if s3Err != nil {
				global.Logger.Log(s3Err.Error(), "failed to upload attachment")
				return fmt.Errorf("failed uploading attachment: %v: %w", s3Err, asynq.SkipRetry)
			}
			attachment.Content = []byte{} // clear the content
			url := fmt.Sprintf("s3://%s/%s", global.Conf.Storage.Bucket, attPath)
			attachment.ContentURL = &url
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
