package api

import (
	"fmt"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"github.com/mailio/go-mailio-server/services"
	"github.com/mailio/go-mailio-server/types"
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
// @Param handshake body types.DIDCommMessage true "didcomm-encrypted+json"
// @Success 200 {object} types.DIDCommMessage
// @Failure 401 {object} api.ApiError "invalid signature"
// @Failure 400 {object} api.ApiError "bad request"
// @Failure 429 {object} api.ApiError "rate limit exceeded"
// @Router /api/v1/mtp/{address}/message [post]
func (ms *MessagingMTPApi) ReceiveMessage(c *gin.Context) {
	address := c.Param("address")
	fmt.Printf("address: %s\n", address)
}
