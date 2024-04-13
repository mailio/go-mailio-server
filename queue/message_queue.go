package queue

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/hibiken/asynq"
	"github.com/mailio/go-mailio-server/global"
	"github.com/mailio/go-mailio-server/repository"
	"github.com/mailio/go-mailio-server/services"
	"github.com/mailio/go-mailio-server/types"
)

type MessageQueue struct {
	ssiService       *services.SelfSovereignService
	userService      *services.UserService
	mtpService       *services.MtpService
	handshakeService *services.HandshakeService
	deliveryService  *services.MessageDeliveryService
	restyClient      *resty.Client
	env              *types.Environment
}

func NewMessageQueue(dbSelector *repository.CouchDBSelector, env *types.Environment) *MessageQueue {

	rcClient := resty.New()
	ssiService := services.NewSelfSovereignService(dbSelector)
	userService := services.NewUserService(dbSelector, env)
	mtpService := services.NewMtpService(dbSelector)
	handshakeService := services.NewHandshakeService(dbSelector)
	deliveryService := services.NewMessageDeliveryService(dbSelector)

	return &MessageQueue{ssiService: ssiService, userService: userService, mtpService: mtpService, handshakeService: handshakeService, deliveryService: deliveryService, restyClient: rcClient, env: env}
}

// Processing of SMTP tasks
func (mqs *MessageQueue) ProcessSMTPTask(ctx context.Context, t *asynq.Task) error {
	var task types.SmtpTask
	if err := json.Unmarshal(t.Payload(), &task); err != nil {
		return fmt.Errorf("json.Unmarshal failed: %v: %w", err, asynq.SkipRetry)
	}
	switch t.Type() {
	case types.QueueTypeSMTPCommSend:
		// send the message
		taskId := t.ResultWriter().TaskID()
		mqs.SendSMTPMessage(task.Address, task.Mail, taskId)
	case types.QueueTypeSMTPCommReceive:
		// receive the message
		// mqs.ReceiveSMTPMessage(task.From, task.Mail)
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
		mqs.DIDCommSendMessage(task.Address, task.DIDCommMessage)
	case types.QueueTypeDIDCommRecv:
		// receive the message
		mqs.DidCommReceiveMessage(task.DIDCommMessage)
	default:
		// no responses on unrecognized messages
		return fmt.Errorf("unexpected task type: %s, %w", t.Type(), asynq.SkipRetry)
	}

	return nil
}

// SendMessage sends encrypted DIDComm message to recipient
func (msq *MessageQueue) DIDCommSendMessage(userAddress string, message *types.DIDCommMessage) error {
	global.Logger.Log("sending from", userAddress, "intent", message.Intent)

	if message.Thid == "" {
		message.Thid = message.ID // if there is no thid, use message id
	}

	// struct to store in local database
	mailioMessage := types.MailioMessage{
		ID:             message.ID,
		From:           message.From,
		DIDCommMessage: message,
		Created:        time.Now().UnixMilli(),
		Folder:         types.MailioFolderSent,
		IsRead:         true, // sent messages are by default read
	}

	//validate recipients (checks if they are valid DIDs and if they are reachable via HTTP/HTTPS)
	recipientDidMap, mtpStatusErrors := msq.validateRecipientDIDs(message)

	// collect endpoints
	endpointMap := make(map[string]string)

	// iterating over recipient map and sending messages
	for _, didDoc := range recipientDidMap {
		// didDoc ID has format e.g. did:mailio:0xabc, while from has web format (e.g. did:web:mail.io#0xabc)
		// find a service endpoint for a recipient from DID Document
		endpoint := msq.extractDIDMessageEndpoint(&didDoc)
		if endpoint == "" {
			// Bad destination address syntax
			mtpStatusErrors = append(mtpStatusErrors, types.NewMTPStatusCode(5, 1, 3, fmt.Sprintf("unable to route message to %s for %s", endpoint, didDoc.ID.String())))
			continue
		}
		endpointMap[endpoint] = endpoint
	}
	// send message to each endpoint extracted from DID documents
	for _, ep := range endpointMap {
		code, sendErr := msq.httpSend(message, ep)
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
