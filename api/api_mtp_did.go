package api

import (
	"encoding/base64"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"github.com/mailio/go-mailio-server/global"
	"github.com/mailio/go-mailio-server/services"
	"github.com/mailio/go-mailio-server/types"
	"github.com/mailio/go-mailio-server/util"
)

type DIDMtpApi struct {
	mtpService *services.MtpService
	validate   *validator.Validate
	env        *types.Environment
}

func NewDIDMtpApi(mtpService *services.MtpService, env *types.Environment) *DIDMtpApi {
	validate := validator.New()

	return &DIDMtpApi{
		mtpService: mtpService,
		validate:   validate,
		env:        env,
	}
}

// Request DID Documents from local database by email hash (digitally signed)
// The request is typically make from remote server method FetchDIDDocuments (above)
// @Summary Request did docouments from this server (must be digitally signed by senders Mailio server)
// @Description Request did documents from this server by email hash (must be digitally signed bny senders Mailio server)
// @Tags Mailio Transfer Protocol
// @Accept json
// @Produce json
// @Param handshake body types.DIDDocumentSignedRequest true "DIDDocumentSignedRequest"
// @Success 200 {object} types.DIDDocumentSignedResponse
// @Failure 401 {object} api.ApiError "invalid signature"
// @Failure 400 {object} api.ApiError "bad request"
// @Failure 429 {object} api.ApiError "rate limit exceeded"
// @Router /api/v1/mtp/did [post]
func (didMtp *DIDMtpApi) GetLocalDIDDocuments(c *gin.Context) {
	// input DIDDocumentSignedRequest
	var input types.DIDDocumentSignedRequest
	if err := c.ShouldBindJSON(&input); err != nil {
		ApiErrorf(c, http.StatusBadRequest, "invalid format")
		return
	}
	err := didMtp.validate.Struct(input)
	if err != nil {
		msg := util.ValidationErrorToMessage(err)
		ApiErrorf(c, http.StatusBadRequest, msg)
		return
	}
	found, notFound, fErr := didMtp.mtpService.GetLocalDIDDocumentsByEmailHash(input.DIDLookupRequest.DIDLookups)
	if fErr != nil {
		ApiErrorf(c, http.StatusBadRequest, "error getting did documents")
		return
	}

	response := types.DIDLookupResponse{
		LookupHeader: types.LookupHeader{
			SignatureScheme: types.Signature_Scheme_EdDSA_X25519,
			Timestamp:       time.Now().UnixMilli(),
		},
		FoundLookups:    found,
		NotFoundLookups: notFound,
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

	signedResponse := types.DIDDocumentSignedResponse{
		DIDLookupResponse: response,
		SignatureBase64:   base64.StdEncoding.EncodeToString(signature),
		CborPayloadBase64: base64.StdEncoding.EncodeToString(cbBytes),
	}

	c.JSON(http.StatusOK, signedResponse)
}
