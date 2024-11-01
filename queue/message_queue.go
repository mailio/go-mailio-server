package queue

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/hibiken/asynq"
	"github.com/mailio/go-mailio-did/did"
	"github.com/mailio/go-mailio-server/global"
	"github.com/mailio/go-mailio-server/repository"
	"github.com/mailio/go-mailio-server/services"
	"github.com/mailio/go-mailio-server/types"
	"github.com/mailio/go-mailio-server/util"
)

type MessageQueue struct {
	ssiService         *services.SelfSovereignService
	userService        *services.UserService
	userProfileService *services.UserProfileService
	mtpService         *services.MtpService
	handshakeService   *services.HandshakeService
	deliveryService    *services.MessageDeliveryService
	s3Service          *services.S3Service
	malwareService     *services.MalwareService
	restyClient        *resty.Client
	env                *types.Environment
}

func NewMessageQueue(dbSelector *repository.CouchDBSelector, env *types.Environment) *MessageQueue {

	rcClient := resty.New()
	ssiService := services.NewSelfSovereignService(dbSelector, env)
	userService := services.NewUserService(dbSelector, env)
	mtpService := services.NewMtpService(dbSelector, env)
	handshakeService := services.NewHandshakeService(dbSelector)
	deliveryService := services.NewMessageDeliveryService(dbSelector)
	userProfileService := services.NewUserProfileService(dbSelector, env)
	malwareService := services.NewMalwareService()
	s3Service := services.NewS3Service(env)

	return &MessageQueue{
		ssiService:         ssiService,
		userService:        userService,
		mtpService:         mtpService,
		handshakeService:   handshakeService,
		deliveryService:    deliveryService,
		malwareService:     malwareService,
		restyClient:        rcClient,
		env:                env,
		userProfileService: userProfileService,
		s3Service:          s3Service,
	}
}

// Processing of SMTP tasks
func (mqs *MessageQueue) ProcessSMTPTask(ctx context.Context, t *asynq.Task) error {
	var task types.SmtpTask
	if err := json.Unmarshal(t.Payload(), &task); err != nil {
		return fmt.Errorf("json.Unmarshal failed: %v: %w", err, asynq.SkipRetry)
	}

	email, meErr := util.ConvertToSmtpEmail(*task.Mail)
	if meErr != nil {
		global.Logger.Log(meErr.Error(), "failed to convert to smtp email", task.Mail)
		return fmt.Errorf("failed to convert to smtp email: %v: %w", meErr, asynq.SkipRetry)
	}

	taskId := t.ResultWriter().TaskID()
	switch t.Type() {
	case types.QueueTypeSMTPCommSend:
		// send the message
		mqs.SendSMTPMessage(task.Address, task.Mail, taskId)
	case types.QueueTypeSMTPCommReceive:
		// receive the message
		mqs.ReceiveSMTPMessage(email, taskId)
	default:
		return fmt.Errorf("unexpected task type: %s, %w", t.Type(), asynq.SkipRetry)
	}
	return nil
}

// processing od DIDComm tasks
func (mqs *MessageQueue) ProcessDIDCommTask(ctx context.Context, t *asynq.Task) error {
	// return nil if task is successfully processed, otherwise return an error.
	var task types.Task
	if err := json.Unmarshal(t.Payload(), &task); err != nil {
		// no responses on unrecognized messages
		return fmt.Errorf("json.Unmarshal failed: %v: %w", err, asynq.SkipRetry)
	}

	// process the message
	switch t.Type() {
	case types.QueueTypeDIDCommSend:
		// send the message
		mqs.DIDCommSendMessage(task.Address, task.DIDCommMessageInput)
	case types.QueueTypeDIDCommRecv:
		// receive the message
		if task.DIDCommMessageInput == nil {
			return fmt.Errorf("DIDCommMessageInput is nil: %w", asynq.SkipRetry)
		}
		mqs.DidCommReceiveMessage(&task.DIDCommMessageInput.DIDCommMessage)
	default:
		// no responses on unrecognized messages
		return fmt.Errorf("unexpected task type: %s, %w", t.Type(), asynq.SkipRetry)
	}

	return nil
}

// SendMessage sends encrypted DIDComm message to recipient
func (msq *MessageQueue) DIDCommSendMessage(userAddress string, input *types.DIDCommMessageInput) error {
	message := input.DIDCommMessage
	global.Logger.Log("sending from", userAddress, "intent", message.Intent)

	if message.Thid == "" {
		message.Thid = message.ID // if there is no thid, use message id
	}

	// struct to store in local database
	mailioMessage := types.MailioMessage{
		ID:             message.ID,
		From:           message.From,
		DIDCommMessage: &message,
		Created:        time.Now().UnixMilli(),
		Folder:         types.MailioFolderSent,
		IsRead:         true, // sent messages are by default read
	}

	//validate recipients (checks if they are valid DIDs and if they are reachable via HTTP/HTTPS)
	// alternatively validateRecipientDIDFromEmails can be used to validate recipients from emails
	recipientDidMap := map[string]did.Document{}
	mtpStatusErrors := []*types.MTPStatusCode{}
	if len(message.To) > 0 {
		recMap, mtpErrors := msq.validateRecipientDIDs(&message)
		recipientDidMap = recMap
		mtpStatusErrors = mtpErrors
	} else if len(message.ToEmails) > 0 {
		recMap, mtpErrors := msq.validateRecipientDIDFromEmails(&message)
		for k, v := range recMap {
			recipientDidMap[k] = v
		}
		mtpStatusErrors = append(mtpStatusErrors, mtpErrors...)
	} else {
		// no recipients
		mtpStatusErrors = append(mtpStatusErrors, types.NewMTPStatusCode(5, 1, 1, "no recipients"))
	}

	// collect endpoints
	endpointMap := make(map[string]string)

	// iterating over recipient map and sending messages
	for _, didDoc := range recipientDidMap {
		// didDoc ID has format e.g. did:mailio:0xabc, while from has web format (e.g. did:web:mail.io#0xabc)
		// find a service endpoint for a recipient from DID Document
		endpoint := util.ExtractDIDMessageEndpoint(&didDoc)
		if endpoint == "" {
			// Bad destination address syntax
			mtpStatusErrors = append(mtpStatusErrors, types.NewMTPStatusCode(5, 1, 3, fmt.Sprintf("unable to route message to %s for %s", endpoint, didDoc.ID.String())))
			continue
		}
		endpointMap[endpoint] = endpoint
	}

	// download attachment data from s3
	for _, att := range message.Attachments {
		if len(att.Data.Links) > 0 {
			for _, link := range att.Data.Links {
				if strings.Contains(link, "?enc=1") {
					url := strings.Replace(link, "?enc=1", "", 1)
					content, dErr := msq.s3Service.DownloadAttachment(url)
					if dErr != nil {
						global.Logger.Log(dErr.Error(), "failed to download attachment")
						// TODO: store message_delivery error?
						return fmt.Errorf("failed downloading attachment: %v: %w", dErr, asynq.SkipRetry)
					}
					att.Data.Base64 = base64.StdEncoding.EncodeToString(content)
				}
			}
			att.Data.Links = nil
		}
	}

	// send message to each endpoint extracted from DID documents
	for _, ep := range endpointMap {
		code, sendErr := msq.httpSend(&message, ep)
		if sendErr != nil {
			if sendErr == types.ErrContinue {
				// on to the next message if this one failed
				mtpStatusErrors = append(mtpStatusErrors, code)
				continue
			}
			return sendErr
		}
	}
	// if no errors, append success message
	if len(mtpStatusErrors) == 0 {
		mtpStatusErrors = append(mtpStatusErrors, types.NewMTPStatusCode(2, 0, 0, "message sent"))
	}
	// store mailioMessage in database (sent folder of the sender)
	_, sErr := msq.userService.SaveMessage(userAddress, &mailioMessage)
	if sErr != nil {
		global.Logger.Log(sErr.Error(), "(sendMessage) failed to save message", userAddress)
		return sErr
	}
	msq.deliveryService.SaveBulkMtpStatusCodes(message.ID, mtpStatusErrors)

	// delete attachments that client wants to delete
	// remove possible attachments to be removed (the cientt reports those when only 1 type of recipient is present, but both encrypted and plain attachments is uploaded)
	for _, att := range input.DeleteAttachments {
		// delete attachment
		link, lpErr := url.Parse(att)
		if lpErr != nil {
			global.Logger.Log(lpErr.Error(), "failed to parse attachment link", att)
			continue
		}
		// extract bucket and path (the path is not completely trusted. So only in userSender folder can it be deleted)
		parts := strings.Split(link.Path, "/")
		fileKey := userAddress + "/" + parts[len(parts)-1]
		if fileKey == "" {
			global.Logger.Log("error", "invalid attachment url", "attachmentUrl", att)
			return fmt.Errorf("invalid attachment url: %v: %w", lpErr, asynq.SkipRetry)
		}
		dErr := msq.s3Service.DeleteAttachment(global.Conf.Storage.Bucket, fileKey)
		if dErr != nil {
			global.Logger.Log(dErr.Error(), "failed to delete attachment", att)
		}
	}
	return nil
}

// SendMessage sends encrypted DIDComm message to recipient
func (msq *MessageQueue) DidCommReceiveMessage(message *types.DIDCommMessage) error {
	global.Logger.Log("received msg intent", message.Intent, "id", message.ID, "from", message.From)
	fmt.Printf("received msg intent %s id %s from %s\n", message.Intent, message.ID, message.From)
	switch message.Intent {
	case types.DIDCommIntentMessage, types.DIDCommIntentHandshake:
		// handle message receive
		msq.handleReceivedDIDCommMessage(message)
	case types.DIDCommIntentDelivery:
		// handle delivery receipt
		msq.handleDIDCommDelivery(message)
	default:
		return fmt.Errorf("unrecognized intent: %s, %w", message.Intent, asynq.SkipRetry)
	}
	return nil
}
