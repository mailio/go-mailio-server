package queue

import (
	"context"
	"encoding/json"
	"fmt"

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
	ssiService         *services.SelfSovereignService
	userService        *services.UserService
	userProfileService *services.UserProfileService
	mtpService         *services.MtpService
	deliveryService    *services.MessageDeliveryService
	s3Service          *services.S3Service
	malwareService     *services.MalwareService
	nonceService       *services.NonceService
	statisticsService  *services.StatisticsService
	userRepo           repository.Repository
	restyClient        *resty.Client
	env                *types.Environment
}

func NewMessageQueue(dbSelector *repository.CouchDBSelector, env *types.Environment) *MessageQueue {

	rcClient := resty.New()
	ssiService := services.NewSelfSovereignService(dbSelector, env)
	userService := services.NewUserService(dbSelector, env)
	mtpService := services.NewMtpService(dbSelector, env)
	deliveryService := services.NewMessageDeliveryService(dbSelector)
	userProfileService := services.NewUserProfileService(dbSelector, env)
	malwareService := services.NewMalwareService()
	s3Service := services.NewS3Service(env)
	statisticsService := services.NewStatisticsService(dbSelector, env)
	nonceService := services.NewNonceService(dbSelector)

	userRepo, urErr := dbSelector.ChooseDB(repository.User)
	if urErr != nil {
		level.Error(global.Logger).Log("msg", "error while choosing db", "err", urErr)
		panic(urErr)
	}

	return &MessageQueue{
		ssiService:         ssiService,
		userService:        userService,
		mtpService:         mtpService,
		deliveryService:    deliveryService,
		malwareService:     malwareService,
		restyClient:        rcClient,
		env:                env,
		userProfileService: userProfileService,
		s3Service:          s3Service,
		userRepo:           userRepo,
		statisticsService:  statisticsService,
		nonceService:       nonceService,
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
		level.Error(global.Logger).Log(meErr.Error(), "failed to convert to smtp email", task.Mail)
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
func (msq *MessageQueue) DidCommReceiveMessage(message *types.DIDCommMessage) error {
	level.Info(global.Logger).Log("received msg intent", message.Intent, "id", message.ID, "from", message.From)
	switch message.Intent {
	case types.DIDCommIntentMessage, types.DIDCommIntentHandshake, types.DIDCommIntentHandshakeRequest, types.DIDCommIntentHandshakeResponse:
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
