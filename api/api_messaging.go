package api

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"github.com/mailio/go-mailio-did/did"
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
// @Param handshake body types.InputDIDCommMessage true "didcomm-encrypted+json"
// @Success 200 {object} types.InputDIDCommMessage
// @Failure 401 {object} api.ApiError "invalid signature"
// @Failure 400 {object} api.ApiError "bad request"
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

	// validate input
	err := ma.validate.Struct(input)
	if err != nil {
		msg := util.ValidationErrorToMessage(err)
		ApiErrorf(c, http.StatusBadRequest, msg)
		return
	}

	// TODO! create a queue, do the validation there, then send the message (also add MailioIntent System message - e.g. user not found, handshake revoked, ...)
	// 1. validate sender (if enabled, if signature valid from JWE)
	// 2. validate recipients (if server understands MTP, if recipients are valid -> use did web format)
	// 3. Sign message with Mailio private key
	// 4. send message
	// 5. return confirmation message from origin server (e.g. mail.io or compatible server). Includes failed messages

	// validate senders DID format (must be: did:mailio:mydomain.com:0xSender)
	fromDID, didErr := did.ParseDID(input.From)
	if didErr != nil {
		global.Logger.Log(didErr.Error(), "sender verification failed")
		return
	}
	expectedDID := "did:mailio:" + global.Conf.Mailio.Domain + ":" + subjectAddress.(string)
	if fromDID.String() != expectedDID {
		ApiErrorf(c, http.StatusBadRequest, "from field invalid")
		return
	}

	//TODO: validate recipients? What should I validate? Maybe if they are valid DIDs so the message can be posted to the correct URLs (get the URLs from DID docs)?
	for _, recipient := range input.EncryptedBody.Recipients {
		kid := recipient.Header.Kid
		rec, didErr := did.ParseDID(kid)
		if didErr != nil {
			ApiErrorf(c, http.StatusBadRequest, fmt.Sprintf("invalid recipient %s", kid))
			return
		}
		fmt.Printf("recipient string: %s\n", rec.String())
		fmt.Printf("recipient protocol: %s\n", rec.Protocol())
		fmt.Printf("recipient value: %s\n", rec.Value())
	}

	// setup server side specific unique IDs
	input.ID = uuid.NewString()
	input.CreatedTime = time.Now().UnixMilli()

	// TODO: send message (POST to collected URL for specific recipient)
	// TODO; response intent message format (check SMTP?)
}
