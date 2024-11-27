package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"github.com/mailio/go-mailio-server/services"
	"github.com/mailio/go-mailio-server/types"
)

type HandshakeApi struct {
	nonceService       *services.NonceService
	mtpService         *services.MtpService
	userService        *services.UserService
	userProfileService *services.UserProfileService
	validate           *validator.Validate
}

func NewHandshakeApi(nonceService *services.NonceService, mtpService *services.MtpService, userService *services.UserService, userProfileService *services.UserProfileService) *HandshakeApi {
	return &HandshakeApi{
		nonceService:       nonceService,
		mtpService:         mtpService,
		userProfileService: userProfileService,
		userService:        userService,
		validate:           validator.New(),
	}
}

// Personal Handshake link
// @Security Bearer
// @Summary Create personal handshake link
// @Description Create personal handshake link
// @Tags Handshake
// @Success 200 {object} types.HandshakeLink
// @Failure 401 {object} api.ApiError "not authorized"
// @Failure 429 {object} api.ApiError "rate limit exceeded"
// @Router /api/v1/handshakeoffer [get]
func (ha *HandshakeApi) PersonalHandshakeLink(c *gin.Context) {
	// extract address from JWS token
	address, exists := c.Get("subjectAddress")
	if !exists {
		ApiErrorf(c, http.StatusUnauthorized, "not authorized to create personal handshake")
		return
	}
	// create a personal handshake link
	profile, pErr := ha.userProfileService.Get(address.(string))
	if pErr != nil {
		ApiErrorf(c, http.StatusNotFound, "user profile not found")
		return
	}

	// domain := global.Conf.Mailio.Domain
	// nonces are typically deleted within 5 minutes. That should be enough time to use the link
	nonce, nErr := ha.nonceService.CreateCustomNonce(16)
	if nErr != nil {
		ApiErrorf(c, http.StatusInternalServerError, "error while creating nonce")
		return
	}

	// create a link with the nonce
	// format: nonce:web:domain:address
	link := types.HandshakeLink{
		Link: nonce.Nonce + ":web:" + profile.Domain + ":" + address.(string),
	}
	c.JSON(http.StatusOK, link)
}
