package api

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
	"github.com/go-playground/validator/v10"
	"github.com/hibiken/asynq"
	"github.com/mailio/go-mailio-server/global"
	"github.com/mailio/go-mailio-server/services"
	"github.com/mailio/go-mailio-server/types"
	"github.com/mailio/go-mailio-server/util"
)

type MessagingApi struct {
	ssiService *services.SelfSovereignService
	validate   *validator.Validate
	env        *types.Environment
}

func NewMessagingApi(ssiService *services.SelfSovereignService, env *types.Environment) *MessagingApi {
	validate := validator.New()

	return &MessagingApi{
		validate:   validate,
		ssiService: ssiService,
		env:        env,
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
// @Failure 401 {object} api.ApiError "invalid signature or unauthorized to send messages"
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

	// default is messaging
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

	// force the from field to be the subject address
	from := fmt.Sprintf("did:web:%s#%s", global.Conf.Mailio.Domain, subjectAddress.(string))
	if input.From != from {
		ApiErrorf(c, http.StatusUnauthorized, "unathorized")
		return
	}

	// intended folder for sender is "sent"
	id, idErr := util.DIDDocumentToUniqueID(&input, types.MailioFolderSent)
	if idErr != nil {
		ApiErrorf(c, http.StatusBadRequest, idErr.Error())
		return
	}
	input.ID = id
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
