package api

import (
	"encoding/base64"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
	"github.com/go-playground/validator/v10"
	"github.com/mailio/go-mailio-server/global"
	"github.com/mailio/go-mailio-server/services"
	"github.com/mailio/go-mailio-server/types"
	"github.com/mailio/go-mailio-server/util"
)

type HandshakeMTPApi struct {
	mtpService *services.MtpService
	validate   *validator.Validate
	env        *types.Environment
}

func NewHandshakeMTPApi(mtpService *services.MtpService, env *types.Environment) *HandshakeMTPApi {
	validate := validator.New()

	return &HandshakeMTPApi{
		mtpService: mtpService,
		validate:   validate,
		env:        env,
	}
}

// Request handshake from local database (digitally signed)
// @Summary Request handshake from this server (must be digitally signed by senders Mailio server)
// @Description Request handshake from this server (must be digitally signed by senders Mailio server)
// @Tags Mailio Transfer Protocol
// @Accept json
// @Produce json
// @Param handshake body types.HandshakeSignedRequest true "HandshakeSignedRequest"
// @Success 200 {object} types.HandshakeSignedResponse
// @Failure 401 {object} api.ApiError "invalid signature"
// @Failure 400 {object} api.ApiError "bad request"
// @Failure 429 {object} api.ApiError "rate limit exceeded"
// @Router /api/v1/mtp/handshake [post]
func (hs *HandshakeMTPApi) GetLocalHandshakes(c *gin.Context) {
	var input types.HandshakeSignedRequest
	if err := c.ShouldBindBodyWith(&input, binding.JSON); err != nil {
		ApiErrorf(c, http.StatusBadRequest, "invalid format")
		return
	}
	err := hs.validate.Struct(input)
	if err != nil {
		msg := util.ValidationErrorToMessage(err)
		ApiErrorf(c, http.StatusBadRequest, msg)
		return
	}

	// return all found handshakes found in the local database
	found, _, err := hs.mtpService.LocalHandshakeLookup(input.HandshakeRequest.SenderAddress, input.HandshakeRequest.HandshakeLookups)
	if err != nil {
		ApiErrorf(c, http.StatusBadRequest, "failed to lookup handshakes")
		return
	}
	response := types.HandshakeResponse{
		Handshakes: found,
		HandshakeHeader: types.LookupHeader{
			SignatureScheme: types.Signature_Scheme_EdDSA_X25519,
			Timestamp:       time.Now().UnixMilli(),
		},
	}

	cbBytes, cbErr := util.CborEncode(response)
	if cbErr != nil {
		ApiErrorf(c, http.StatusBadRequest, "failed to cbor encode response")
		return
	}

	signature, sErr := util.Sign(cbBytes, global.PrivateKey)
	if sErr != nil {
		ApiErrorf(c, http.StatusBadRequest, "failed to sign response")
		return
	}

	signedResponse := types.HandshakeSignedResponse{
		HandshakeResponse: response,
		SignatureBase64:   base64.StdEncoding.EncodeToString(signature),
		CborPayloadBase64: base64.StdEncoding.EncodeToString(cbBytes),
	}
	c.JSON(http.StatusOK, signedResponse)
}
