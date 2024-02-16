package services

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/google/uuid"
	"github.com/hibiken/asynq"
	"github.com/mailio/go-mailio-did/did"
	"github.com/mailio/go-mailio-server/global"
	"github.com/mailio/go-mailio-server/repository"
	"github.com/mailio/go-mailio-server/types"
)

type MessageQueueService struct {
	dbSelector repository.DBSelector
}

func NewMessageQueueService(dbSelector repository.DBSelector) *MessageQueueService {
	return &MessageQueueService{dbSelector: dbSelector}
}

func (mqs *MessageQueueService) ProcessTask(ctx context.Context, t *asynq.Task) error {
	// return nil if task is successfully processed, otherwise return an error.
	var task types.Task
	if err := json.Unmarshal(t.Payload(), &task); err != nil {
		return err
	}

	// process the message
	switch t.Type() {
	case types.QueueTypeDIDCommSend:
		// send the message
		mqs.SendMessage(task.Address, task.DIDCommMessage)
		// ...
	case types.QueueTypeDIDCommRecv:
		// receive the message
		// ...
	default:
		return fmt.Errorf("unexpected task type: %s", t.Type())
	}

	return nil
}

func (msq *MessageQueueService) SendMessage(userAddress string, message *types.DIDCommMessage) error {
	fmt.Printf("Sending message: %v\n", message)
	// validate senders DID format (must be: did:mailio:mydomain.com:0xSender)
	fromDID, didErr := did.ParseDID(message.From)
	if didErr != nil {
		global.Logger.Log(didErr.Error(), "sender verification failed")
		return didErr
	}
	didAddressSplit := strings.Split(fromDID.String(), ":")
	fromDidAddress := ""
	if len(didAddressSplit) > 0 {
		fromDidAddress = didAddressSplit[len(didAddressSplit)-1]
	}
	if fromDidAddress != userAddress {
		return fmt.Errorf("from field invalid")
	}

	rc := resty.New()

	//TODO: validate recipients? What should I validate? Maybe if they are valid DIDs so the message can be posted to the correct URLs (get the URLs from DID docs)?
	for _, recipient := range message.To {
		rec, didErr := did.ParseDID(recipient)
		if didErr != nil {
			global.Logger.Log(didErr.Error(), "recipient verification failed")
			return didErr
		}
		fmt.Printf("recipient string: %s\n", rec.String())
		fmt.Printf("recipient protocol: %s\n", rec.Protocol())
		fmt.Printf("recipient value: %s\n", rec.Value())
		lastColon := strings.LastIndex(rec.Value(), ":")
		if lastColon < 0 {
			global.Logger.Log("invalid recipient")
			return fmt.Errorf("invalid recipient %s", recipient)
		}
		url := rec.Value()[:lastColon]
		userAddress := rec.Value()[lastColon+1:]
		fmt.Printf("url: %s\n", url)
		fmt.Printf("userAddress: %s\n", userAddress)
		protocol := "https"
		if strings.Contains(url, "localhost") || strings.Contains(url, "127.0.0.1") {
			protocol = "http"
		}
		var result did.Document
		response, rErr := rc.R().SetBody(message).SetResult(&result).Get(fmt.Sprintf("%s://%s/%s/did.json", protocol, url, userAddress))
		if rErr != nil {
			global.Logger.Log(rErr.Error(), "failed to validate recipient")
			return rErr
		}
		if response.IsError() {
			if response.StatusCode() == http.StatusNotFound {
				global.Logger.Log("recipient not found", "failed to validate recipient")
				//TODO! do not return errors, but collect "not found" DIDCommMessage
				continue
			}
			global.Logger.Log(fmt.Sprintf("failed to validate recipient %s", recipient), "failed to validate recipient")
			return fmt.Errorf("failed to validate recipient %s", recipient)
		}
		fmt.Printf("response: %v\n", result)
	}

	// setup server side specific unique IDs
	message.ID = uuid.NewString()
	message.CreatedTime = time.Now().UnixMilli()

	// TODO: send message (POST to collected URL for specific recipient)
	// TODO; response intent message format (check SMTP?)
	return nil
}
