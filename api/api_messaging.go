package api

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"github.com/hibiken/asynq"
	"github.com/mailio/go-mailio-server/global"
	"github.com/mailio/go-mailio-server/services"
	"github.com/mailio/go-mailio-server/types"
	"github.com/mailio/go-mailio-server/util"
)

type MessagingApi struct {
	handshakeService *services.HandshakeService
	mtpService       *services.MtpService
	validate         *validator.Validate
	env              *types.Environment
}

func NewMessagingApi(handshakeService *services.HandshakeService, mtpService *services.MtpService, env *types.Environment) *MessagingApi {
	validate := validator.New()

	return &MessagingApi{
		handshakeService: handshakeService,
		mtpService:       mtpService,
		validate:         validate,
		env:              env,
	}
}

// Send end-to-end encrypted message to a DID recipients
// @Summary Send end-to-end encrypted message to DID recipients
// @Security Bearer
// @Description Send end-to-end encrypted message to DID recipients
// @Tags Messaging
// @Accept json
// @Produce json
// @Param handshake body types.DIDCommMessage true "didcomm-encrypted+json"
// @Success 202 {object} types.DIDCommApiResponse
// @Failure 400 {object} api.ApiError "bad request"
// @Failure 401 {object} api.ApiError "invalid signature"
// @Failure 429 {object} api.ApiError "rate limit exceeded"
// @Router /api/v1/didmessage [post]
func (ma *MessagingApi) SendDIDMessage(c *gin.Context) {
	subjectAddress, exists := c.Get("subjectAddress")
	if !exists {
		ApiErrorf(c, http.StatusInternalServerError, "jwt invalid")
		return
	}

	// input DIDCommMessage
	var input types.DIDCommMessage
	if err := c.ShouldBindBodyWith(&input, binding.JSON); err != nil {
		ApiErrorf(c, http.StatusBadRequest, "invalid format")
		return
	}

	if input.Intent == "" {
		input.Intent = types.DIDCommIntentMessage
	}

	// validate input
	err := ma.validate.Struct(input)
	if err != nil {
		msg := util.ValidationErrorToMessage(err)
		ApiErrorf(c, http.StatusBadRequest, msg)
		return
	}
	input.ID = uuid.New().String()
	input.CreatedTime = time.Now().UTC().UnixMilli()

	task := &types.Task{
		Address:        subjectAddress.(string),
		DIDCommMessage: &input,
	}
	sendTask, tErr := types.NewDIDCommSendTask(task)
	if tErr != nil {
		ApiErrorf(c, http.StatusInternalServerError, tErr.Error())
		return
	}

	taskInfo, tqErr := ma.env.TaskClient.Enqueue(sendTask,
		asynq.MaxRetry(3),             // max number of times to retry the task
		asynq.Timeout(60*time.Second), // max time to process the task
		asynq.TaskID(input.ID),        // unique task id
		asynq.Unique(time.Second*10))  // unique for 10 seconds (preventing multiple equal messages in the queue)
	if tqErr != nil {
		global.Logger.Log(tqErr.Error(), "failed to send message")
		ApiErrorf(c, http.StatusInternalServerError, "failed to send message")
		return
	}
	global.Logger.Log(fmt.Sprintf("message sent: %s", taskInfo.ID), "message queued")

	c.JSON(http.StatusAccepted, types.DIDCommApiResponse{ID: input.ID})
}
