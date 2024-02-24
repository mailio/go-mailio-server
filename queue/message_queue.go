package queue

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-kit/log/level"
	"github.com/go-resty/resty/v2"
	"github.com/hibiken/asynq"
	"github.com/mailio/go-mailio-server/global"
	"github.com/mailio/go-mailio-server/repository"
	"github.com/mailio/go-mailio-server/services"
	"github.com/mailio/go-mailio-server/types"
	"github.com/mailio/go-mailio-server/util"
)

type MessageQueue struct {
	ssiService  *services.SelfSovereignService
	userService *services.UserService
	restyClient *resty.Client
}

func NewMessageQueue(dbSelector *repository.CouchDBSelector) *MessageQueue {

	rcClient := resty.New()
	ssiService := services.NewSelfSovereignService(dbSelector)
	userService := services.NewUserService(dbSelector)

	return &MessageQueue{ssiService: ssiService, userService: userService, restyClient: rcClient}
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
			senderSkipped = true
			continue
		}
		// find a service endpoint for a recipient from DID Document
		endpoint := msq.extractDIDMessageEndpoint(&didDoc)
		if endpoint == "" {
			// Bad destination address syntax
			mailioMessage.MTPStatusCodes = append(mailioMessage.MTPStatusCodes, &types.MTPStatusCode{
				Class:       5, // permanent failure
				Subject:     1, // address status
				Detail:      3, // Bad destination address syntax
				Description: fmt.Sprintf("unable to route message to %s for %s", endpoint, didDoc.ID.String()),
			})
			continue
		} else {

			//
			request := &types.DIDCommRequest{
				DIDCommMessage:  message,
				SignatureScheme: types.Signature_Scheme_EdDSA_X25519,
				Timestamp:       time.Now().UnixMilli(),
			}
			cborPayload, cErr := util.CborEncode(request)
			if cErr != nil {
				level.Error(global.Logger).Log("msg", "failed to cbor encode request", "err", cErr)
				return fmt.Errorf("failed to cbor encode request: %v, %w", cErr, asynq.SkipRetry)
			}
			signature, sErr := util.Sign(cborPayload, global.PrivateKey)
			if sErr != nil {
				level.Error(global.Logger).Log("msg", "failed to sign request", "err", sErr)
				return fmt.Errorf("failed to sign request: %v, %w", sErr, asynq.SkipRetry)
			}

			signedRequest := &types.DIDCommSignedRequest{
				DIDCommRequest:    request,
				CborPayloadBase64: base64.StdEncoding.EncodeToString(cborPayload),
				SignatureBase64:   base64.StdEncoding.EncodeToString(signature),
				SenderDomain:      global.Conf.Host,
			}

			var responseResult types.MTPStatusCode

			response, rErr := msq.restyClient.R().SetBody(signedRequest).SetResult(&responseResult).Post(endpoint)
			if rErr != nil {
				global.Logger.Log(rErr.Error(), "failed to send message", endpoint)
				mailioMessage.MTPStatusCodes = append(mailioMessage.MTPStatusCodes, &types.MTPStatusCode{
					Class:       5, // permanent failure
					Subject:     4, // network and routing status
					Detail:      4, // unable to route
					Description: fmt.Sprintf("failed to send message to %s", didDoc.ID.String()),
				})
				continue
			}
			if response.IsError() {
				// if response.StatusCode() >= 405 && response.StatusCode() < 500 {
				// 	//TODO! should re-queue for later time?
				// } else {

				// }
				global.Logger.Log(response.String(), "failed to send message", endpoint)
				mailioMessage.MTPStatusCodes = append(mailioMessage.MTPStatusCodes, &types.MTPStatusCode{
					Class:       4, // temporary failure
					Subject:     4, // network and routing status
					Detail:      4, // unable to route
					Description: fmt.Sprintf("failed to send message to %s", didDoc.ID.String()),
				})
				continue
			}
		}
	}

	if len(mailioMessage.MTPStatusCodes) == 0 {
		mailioMessage.MTPStatusCodes = append(mailioMessage.MTPStatusCodes, &types.MTPStatusCode{
			Class:       2, // success
			Subject:     0, // other or undefined status
			Detail:      0, // other or undefined status
			Description: "message sent successfully",
		})
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
		//TODO! store message in database
		//TODO! return Message error
	case types.DIDCommIntentError:
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
