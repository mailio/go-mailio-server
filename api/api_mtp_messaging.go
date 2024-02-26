package api

import (
	"encoding/base64"
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

type MessagingMTPApi struct {
	handshakeService *services.HandshakeService
	mtpService       *services.MtpService
	validate         *validator.Validate
	env              *types.Environment
}

func NewMessagingMTPApi(handshakeService *services.HandshakeService, mtpService *services.MtpService, env *types.Environment) *MessagingMTPApi {
	validate := validator.New()

	return &MessagingMTPApi{
		handshakeService: handshakeService,
		mtpService:       mtpService,
		validate:         validate,
		env:              env,
	}
}

// Receive end-to-end encrypted message
// @Summary Receive end-to-end encrypted message
// @Description Receive end-to-end encrypted message
// @Tags Mailio Transfer Protocol
// @Accept json
// @Produce json
// @Param handshake body types.DIDCommSignedRequest true "didcomm signed request"
// @Success 200 {object} types.DIDCommApiResponse
// @Failure 401 {object} api.ApiError "invalid signature"
// @Failure 400 {object} api.ApiError "bad request"
// @Failure 429 {object} api.ApiError "rate limit exceeded"
// @Router /api/v1/mtp/message [post]
func (ms *MessagingMTPApi) ReceiveMessage(c *gin.Context) {

	// input DIDCommMessage
	var input types.DIDCommSignedRequest
	if err := c.ShouldBindBodyWith(&input, binding.JSON); err != nil {
		ApiErrorf(c, http.StatusBadRequest, "invalid format")
		return
	}
	vErr := ms.validate.Struct(input)
	if vErr != nil {
		msg := util.ValidationErrorToMessage(vErr)
		ApiErrorf(c, http.StatusBadRequest, msg)
		return
	}

	// digitially sign response and send confirmation receipt
	resp := &types.DIDCommSignedResponse{
		DIDCommResponse: &types.DIDCommResponse{
			Response: &types.DIDCommApiResponse{
				ID: input.DIDCommRequest.DIDCommMessage.ID,
			},
			SignatureScheme: types.Signature_Scheme_EdDSA_X25519,
			Timestamp:       time.Now().UnixMilli(),
		},
		CborPayloadBase64: "",
		SignatureBase64:   "",
		SenderDomain:      global.Conf.Host,
	}
	cbBytes, cbErr := util.CborEncode(resp.DIDCommResponse)
	if cbErr != nil {
		global.Logger.Log(cbErr.Error(), "failed to cbor encode response")
		ApiErrorf(c, http.StatusInternalServerError, "failed to cbor encode response")
		return
	}
	signature, sErr := util.Sign(cbBytes, global.PrivateKey)
	if sErr != nil {
		global.Logger.Log(sErr.Error(), "failed to sign response")
		ApiErrorf(c, http.StatusInternalServerError, "failed to sign response")
		return
	}
	resp.CborPayloadBase64 = base64.StdEncoding.EncodeToString(cbBytes)
	resp.SignatureBase64 = base64.StdEncoding.EncodeToString(signature)

	// create a receive task with DIDCommMessage
	task := &types.Task{
		DIDCommMessage: input.DIDCommRequest.DIDCommMessage,
	}

	receiveTask, tErr := types.NewDIDCommReceiveTask(task)
	if tErr != nil {
		global.Logger.Log(tErr.Error(), "failed to create task")
		ApiErrorf(c, http.StatusInternalServerError, "failed to create task")
		return
	}

	taskInfo, tqErr := ms.env.TaskClient.Enqueue(receiveTask,
		asynq.MaxRetry(3),                                    // max number of times to retry the task
		asynq.Timeout(60*time.Second),                        // max time to process the task
		asynq.TaskID(input.DIDCommRequest.DIDCommMessage.ID), // unique task id
		asynq.Unique(time.Second*10))                         // unique for 10 seconds (preventing multiple equal messages in the queue)
	if tqErr != nil {
		global.Logger.Log(tqErr.Error(), "failed to send message")
		ApiErrorf(c, http.StatusInternalServerError, "failed to send message")
		return
	}
	global.Logger.Log("message received", input.DIDCommRequest.DIDCommMessage.ID, "task id", taskInfo.ID)

	c.JSON(http.StatusAccepted, resp)
}
