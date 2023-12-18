package api

import (
	"encoding/base64"
	"fmt"
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
	handshakeService *services.HandshakeService
	domainService    *services.DomainService
	validate         *validator.Validate
	env              *types.Environment
}

func NewHandshakeMTPApi(handshakeService *services.HandshakeService, domainService *services.DomainService, env *types.Environment) *HandshakeMTPApi {
	validate := validator.New()

	return &HandshakeMTPApi{
		handshakeService: handshakeService,
		domainService:    domainService,
		validate:         validate,
		env:              env,
	}
}

// Request handshake from remote server (digitally signed)
// @Summary Request handshake from server (digitally signed)
// @Description Request handshake from server (digitally signed)
// @Tags Mailio Transfer Protocol
// @Accept json
// @Produce json
// @Param handshake body types.HandshakeLookups true "HandshakeLookups"
// @Success 200 {object} types.HandshakeSignedResponse
// @Failure 401 {object} api.ApiError "invalid signature"
// @Failure 400 {object} api.ApiError "bad request"
// @Failure 429 {object} api.ApiError "rate limit exceeded"
// @Router /api/v1/mtp/requesthandshakelookup [post]
func (hs *HandshakeMTPApi) RequestLookup(c *gin.Context) {
	address, exists := c.Get("subjectAddress")
	if !exists {
		ApiErrorf(c, http.StatusBadRequest, "not authorized")
		return
	}
	fmt.Printf("address: %s", address.(string))
	//TODO: check if server is in cache and if it's mailio server
	//TODO: 1. if not mailio server, then return email
	//TODO: 2. if mailio server and younger than 24 hours, then return handshake
	//TODO  3. if mailio server and older than 24 hours, then request handshake
	//TODO: check cache if it should return default server handshake

	//TODO: read the handshake lookups

	// request := &types.HandshakeSignedRequest{
	// 	SenderDomain: global.Conf.Host,
	// 	HandshakeRequest: types.HandshakeRequest{
	// 		SenderAddress:                address.(string),
	// 		ReturnDefaultServerHandshake: true,
	// 		HandshakeLookups:             nil,
	// 		HandshakeHeader: types.HandshakeHeader{
	// 			SignatureScheme:       types.Signature_Scheme_EdDSA_X25519,
	// 			Timestamp:             time.Now().UnixMilli(),
	// 			EmailLookupHashScheme: types.EmailLookupHashScheme_SC_N32768_R8_P1_L32_B64,
	// 		},
	// 	},
	// }

}

// Request handshake from local database (digitally signed)
// @Summary Request handshake from server (digitally signed)
// @Description Request handshake from server (digitally signed)
// @Tags Mailio Transfer Protocol
// @Accept json
// @Produce json
// @Param handshake body types.HandshakeSignedRequest true "HandshakeSignedRequest"
// @Success 200 {object} types.HandshakeSignedResponse
// @Failure 401 {object} api.ApiError "invalid signature"
// @Failure 400 {object} api.ApiError "bad request"
// @Failure 429 {object} api.ApiError "rate limit exceeded"
// @Router /api/v1/mtp/handshakelookup [post]
func (hs *HandshakeMTPApi) Lookup(c *gin.Context) {
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
	handshakeContents, err := hs.handshakeService.LookupHandshakeForMTP(&input.HandshakeRequest)
	if err != nil {
		ApiErrorf(c, http.StatusBadRequest, "failed to lookup handshakes")
		return
	}
	response := types.HandshakeResponse{
		Handshakes: handshakeContents,
		HandshakeHeader: types.HandshakeHeader{
			SignatureScheme: types.Signature_Scheme_EdDSA_X25519,
			Timestamp:       time.Now().UnixMilli(),
		},
	}

	cbBytes, cbErr := hs.env.MailioCrypto.CborEncode(response)
	if cbErr != nil {
		ApiErrorf(c, http.StatusBadRequest, "failed to cbor encode response")
		return
	}
	signature, sErr := hs.env.MailioCrypto.Sign(cbBytes, base64.StdEncoding.EncodeToString(global.PrivateKey))
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
