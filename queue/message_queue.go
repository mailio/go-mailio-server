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
	ssiService  *services.SelfSovereignService
	userService *services.UserService
	mtpService  *services.MtpService
	restyClient *resty.Client
}

func NewMessageQueue(dbSelector *repository.CouchDBSelector) *MessageQueue {

	rcClient := resty.New()
	ssiService := services.NewSelfSovereignService(dbSelector)
	userService := services.NewUserService(dbSelector)
	mtpService := services.NewMtpService(dbSelector)

	return &MessageQueue{ssiService: ssiService, userService: userService, mtpService: mtpService, restyClient: rcClient}
}

func (mqs *MessageQueue) ProcessTask(ctx context.Context, t *asynq.Task) error {
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
		mqs.SendMessage(task.Address, task.DIDCommMessage)
	case types.QueueTypeDIDCommRecv:
		// receive the message
		mqs.ReceiveMessage(task.DIDCommMessage)
	default:
		// no responses on unrecognized messages
		return fmt.Errorf("unexpected task type: %s, %w", t.Type(), asynq.SkipRetry)
	}

	return nil
}

// SendMessage sends encrypted DIDComm message to recipient
func (msq *MessageQueue) SendMessage(userAddress string, message *types.DIDCommMessage) error {
	global.Logger.Log("sending from", userAddress, "intent", message.Intent)

	// struct to store in local database
	mailioMessage := types.MailioMessage{
		ID:             message.ID,
		DIDCommMessage: message,
		Created:        time.Now().UnixMilli(),
		Folder:         types.MailioFolderSent,
		IsRead:         true, // sent messages are by default read
		MTPStatusCodes: []*types.MTPStatusCode{},
	}

	// validate sender DID
	fromDID, sndrErr := msq.validateSenderDID(message, userAddress)
	if sndrErr != nil {
		// if sender cannot be validated, no retryies are allowed. Message fails permanently
		return sndrErr
	}

	//validate recipients (checks if they are valid DIDs and if they are reachable via HTTP/HTTPS)
	recipientDidMap := msq.validateRecipientDIDs(&mailioMessage, message)

	// skip sender (but only once, since sending to one-self is allowed)
	senderSkipped := false
	for _, didDoc := range recipientDidMap {
		// didDoc ID has format e.g. did:mailio:0xabc, while from has web format (e.g. did:web:mail.io#0xabc)
		if didDoc.ID.Value() == fromDID.Fragment() && !senderSkipped {
			// sender skipping is allowed only once due to the original sender being able to decrypt their own message in the sent folder
			senderSkipped = true
			continue
		}
		// find a service endpoint for a recipient from DID Document
		endpoint := msq.extractDIDMessageEndpoint(&didDoc)
		if endpoint == "" {
			// Bad destination address syntax
			types.AppendMTPStatusCodeToMessage(&mailioMessage, 5, 1, 3, fmt.Sprintf("unable to route message to %s for %s", endpoint, didDoc.ID.String()))
			continue
		} else {
			// sign and send message to remote recipient
			sendErr, code := msq.httpSend(message, didDoc, endpoint)
			if sendErr != nil {
				if sendErr == types.ErrContinue {
					// on to the next message if this one failed
					mailioMessage.MTPStatusCodes = append(mailioMessage.MTPStatusCodes, code)
					continue
				}
				return sendErr
			}
		}
	}

	if len(mailioMessage.MTPStatusCodes) == 0 {
		types.AppendMTPStatusCodeToMessage(&mailioMessage, 2, 0, 0, "message sent successfully")
	}
	// store mailioMessage in database (sent folder of the sender)
	_, sErr := msq.userService.SaveMessage(userAddress, &mailioMessage)
	if sErr != nil {
		global.Logger.Log(sErr.Error(), "failed to save message", userAddress)
		return sErr
	}
	return nil
}

// SendMessage sends encrypted DIDComm message to recipient
func (msq *MessageQueue) ReceiveMessage(message *types.DIDCommMessage) error {
	global.Logger.Log("intent", message.Intent)
	switch message.Intent {
	case types.DIDCommIntentMessage:
		msq.handleReceivedDIDCommMessage(message)
	case types.DIDCommIntentDelivery:
		//TODO! store message in database
	case types.DIDCommIntentHandshake:
		//TODO! retrieve requested handshake
		//TODO! return Message error
	default:
		//TODO! return Message error
		return fmt.Errorf("unexpected intent: %s", message.Intent)

	}
	return nil
}
