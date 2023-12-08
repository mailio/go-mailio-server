package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"github.com/mailio/go-mailio-server/services"
	"github.com/mailio/go-mailio-server/types"
	"github.com/mailio/go-mailio-server/util"
)

type HandshakeMTPApi struct {
	handshakeService *services.HandshakeService
	validate         *validator.Validate
}

func NewHandshakeMTPApi(handshakeService *services.HandshakeService) *HandshakeMTPApi {
	validate := validator.New()

	return &HandshakeMTPApi{
		handshakeService: handshakeService,
		validate:         validate,
	}
}

// Request handshake from server (digitally signed)
// @Summary Request handshake from server (digitally signed)
// @Description Request handshake from server (digitally signed)
// @Tags Mailio Transfer Protocol for Handshakes
// @Accept json
// @Produce json
// @Param handshake body types.Handshake true "Handshake"
// @Success 200 {object} types.HandshakeSignedRequest
// @Failure 401 {object} api.ApiError "invalid signature"
// @Failure 400 {object} api.ApiError "bad request"
// @Failure 429 {object} api.ApiError "rate limit exceeded"
// @Router /api/v1/mtp/handshakelookup [post]
func (hs *HandshakeMTPApi) RequestHandshakes(c *gin.Context) {
	var input types.HandshakeSignedRequest
	if err := c.ShouldBindJSON(&input); err != nil {
		ApiErrorf(c, http.StatusBadRequest, "invalid format")
		return
	}
	err := hs.validate.Struct(input)
	if err != nil {
		msg := util.ValidationErrorToMessage(err)
		ApiErrorf(c, http.StatusBadRequest, msg)
		return
	}
	hs.handshakeService.LookupHandshakeForMTP(&input.HandshakeRequest)
}
