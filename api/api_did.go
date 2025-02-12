package api

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-kit/log/level"
	"github.com/go-playground/validator/v10"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/mailio/go-mailio-did/did"
	"github.com/mailio/go-mailio-server/global"
	"github.com/mailio/go-mailio-server/services"
	"github.com/mailio/go-mailio-server/types"
	"github.com/mailio/go-mailio-server/util"
)

type DIDApi struct {
	ssiService *services.SelfSovereignService
	mtpService *services.MtpService
	validate   *validator.Validate
}

func NewDIDApi(ssiService *services.SelfSovereignService, mtpService *services.MtpService) *DIDApi {
	return &DIDApi{
		ssiService: ssiService,
		mtpService: mtpService,
		validate:   validator.New(),
	}
}

// Server DID
// @Summary Mailio Server DID Document (public keys)
// @Description Returns a DID Document
// @Tags Decentralized Identifiers
// @Success 200 {object} did.Document
// @Failure 429 {object} api.ApiError "rate limit exceeded"
// @Failure 500 {object} api.ApiError "error creating server did"
// @Accept json
// @Produce json
// @Router /.well-known/did.json [get]
func (did *DIDApi) CreateServerDID(c *gin.Context) {

	didDoc, err := util.CreateMailioDIDDocument()
	if err != nil {
		ApiErrorf(c, http.StatusInternalServerError, "error creating did: %s", err)
		return
	}
	didDoc.Authentication = nil
	c.JSON(http.StatusOK, didDoc)
}

// Server DID Configuration
// @Summary Mailio Server DID Configuration
// @Description Returns a DID Configuration
// @Tags Decentralized Identifiers
// @Failure 429 {object} api.ApiError "rate limit exceeded"
// @Failure 500 {object} api.ApiError "error creating server did configuration"
// @Accept json
// @Produce json
// @Router /.well-known/did-configuration.json [get]
func (da *DIDApi) CreateServerDIDConfiguration(c *gin.Context) {

	config := map[string]interface{}{
		"@context": "https://identity.foundation/.well-known/did-configuration/v1",
	}

	vc := did.NewVerifiableCredential(global.MailioDID.String())
	vc.Context = []string{"https://www.w3.org/2018/credentials/v1",
		"https://identity.foundation/.well-known/did-configuration/v1"}
	vc.Issuer = global.MailioDID.String()
	vc.IssuanceDate = time.UnixMilli(global.MailioKeysCreated)
	vc.Type = []string{"VerifiableCredential", "DomainLinkageCredential"}
	vc.CredentialSubject = did.CredentialSubject{
		ID:     global.MailioDID.String(),
		Origin: fmt.Sprintf("https://%s", global.Conf.Mailio.ServerDomain),
	}

	// JWT version of the above proof as an alternative format
	jwtToken, jwtErr := jwt.NewBuilder().
		Issuer(global.MailioDID.String()).
		Subject(global.MailioDID.String()).
		NotBefore(time.Now().UTC()).
		Build()
	if jwtErr != nil {
		ApiErrorf(c, http.StatusInternalServerError, "error creating jwt: %s", jwtErr)
		return
	}

	jwtToken.Set("vc", vc)
	jwtSigned, jwtErr := jwt.Sign(jwtToken, jwt.WithKey(jwa.EdDSA, global.PrivateKey))
	if jwtErr != nil {
		ApiErrorf(c, http.StatusInternalServerError, "error signing jwt: %s", jwtErr)
		return
	}

	// proof section
	pErr := vc.CreateProof(global.PrivateKey)
	if pErr != nil {
		ApiErrorf(c, http.StatusInternalServerError, "error creating proof: %s", pErr)
		return
	}

	config["linked-dids"] = []interface{}{vc, string(jwtSigned)}

	c.JSON(http.StatusOK, config)
}

// Returns users DID document based on the mailio address
// @Summary Resolve users DID document
// @Description Returns users DID document based on mailio address
// @Tags Decentralized Identifiers
// @Accept json
// @Produce json
// @Param address path string true "Mailio address"
// @Success 200 {object} did.Document
// @Failure 429 {object} api.ApiError "rate limit exceeded"
// @Failure 404 {object} api.ApiError "DID not found"
// @Failure 400 {object} api.ApiError "Invalid DID"
// @Router /{address}/did.json [get]
func (did *DIDApi) GetDIDDocument(c *gin.Context) {
	address := c.Param("address")
	if address == "" {
		ApiErrorf(c, http.StatusNotFound, "address not found")
		return
	}

	resolved, err := did.ssiService.GetDIDDocument(address)
	if err != nil {
		if err == types.ErrNotFound {
			ApiErrorf(c, http.StatusNotFound, "did not found")
			return
		}
		ApiErrorf(c, http.StatusBadRequest, "error resolving did")
		return
	}
	c.JSON(http.StatusOK, resolved)
}

// @Summary Fetch all DID documents by email hash (local and remote)
// @Description Fetch all DID documents by email hash (local and remote)
// @Security Bearer
// @Tags Messaging
// @Accept json
// @Produce json
// @Param lookups body types.InputDIDLookup true "InputDIDLookup"
// @Success 200 {object} types.OutputDIDLookup
// @Failure 404 {object} api.ApiError "DID not found"
// @Failure 429 {object} api.ApiError "rate limit exceeded"
// @Failure 400 {object} api.ApiError "invalid email address"
// @Failure 500 {object} api.ApiError "error fetching did documents"
// @Router /api/v1/resolve/did [post]
func (da *DIDApi) FetchDIDDocumentsByEmailHash(c *gin.Context) {
	address, exists := c.Get("subjectAddress")
	if !exists {
		ApiErrorf(c, http.StatusUnauthorized, "not authorized to create personal handshake")
		return
	}
	// Fetch all DID documents (local and remote)
	var input types.InputDIDLookup
	if err := c.ShouldBindJSON(&input); err != nil {
		ApiErrorf(c, http.StatusBadRequest, "invalid format")
		return
	}
	err := da.validate.Struct(input)
	if err != nil {
		msg := util.ValidationErrorToMessage(err)
		ApiErrorf(c, http.StatusBadRequest, msg)
		return
	}
	found, notFound, fErr := da.mtpService.FetchDIDDocuments(address.(string), input.Lookups)
	if fErr != nil {
		if fErr == types.ErrInvalidEmail {
			ApiErrorf(c, http.StatusBadRequest, "invalid email format")
			return
		}
		ApiErrorf(c, http.StatusInternalServerError, "error fetching did documents")
		return
	}

	c.JSON(http.StatusOK, types.OutputDIDLookup{
		Found:    found,
		NotFound: notFound,
	})
}

// @Summary Fetch all DID documents by Web DID (local and remote)
// @Description Fetch all DID documents by Web DID (local and remote)
// @Security Bearer
// @Tags Messaging
// @Accept json
// @Produce json
// @Param webdid body types.InputWebDIDLookup true "InputWebDIDLookup"
// @Success 200 {object} types.OutputDIDLookup
// @Failure 404 {object} api.ApiError "DID not found"
// @Failure 429 {object} api.ApiError "rate limit exceeded"
// @Failure 400 {object} api.ApiError "invalid DID resolution"
// @Failure 500 {object} api.ApiError "server error"
// @Router /api/v1/resolve/webdid [post]
func (da *DIDApi) FetchDIDByWebDID(c *gin.Context) {
	_, exists := c.Get("subjectAddress")
	if !exists {
		ApiErrorf(c, http.StatusUnauthorized, "not authorized to create personal handshake")
		return
	}
	var input types.InputWebDIDLookup
	if err := c.ShouldBindJSON(&input); err != nil {
		ApiErrorf(c, http.StatusBadRequest, "invalid format")
		return
	}
	err := da.validate.Struct(input)
	if err != nil {
		msg := util.ValidationErrorToMessage(err)
		ApiErrorf(c, http.StatusBadRequest, msg)
		return
	}
	found := make([]*types.DIDLookup, 0)
	notFound := make([]*types.DIDLookup, 0)
	for _, webDid := range input.DIDs {

		// get the senders DID and get the service endpoint where message was sent from
		fromDID, fdErr := did.ParseDID(webDid)
		if fdErr != nil {
			//the sender cannot be validated, no retryies are allowed. Message fails permanently
			level.Error(global.Logger).Log("msg", fdErr.Error(), "context", "failed to parse sender DID", "webDid", webDid)
			ApiErrorf(c, http.StatusBadRequest, "invalid DID")
			return
		}

		didDoc, err := da.ssiService.FetchDIDByWebDID(fromDID)
		if err != nil {
			if err == types.ErrNotFound {
				notFound = append(notFound, &types.DIDLookup{
					SupportsMailio: false,
					DIDDocument:    didDoc,
					MTPStatusCode: &types.MTPStatusCode{
						Class:       1,
						Subject:     1,
						Detail:      1,
						Description: "DID not found",
						Timestamp:   time.Now().UnixMilli(),
						Address:     fromDID.Fragment(),
					},
				})
				continue
			}
			if err == types.ErrInvalidFormat {
				notFound = append(notFound, &types.DIDLookup{
					SupportsMailio: false,
					DIDDocument:    didDoc,
					MTPStatusCode: &types.MTPStatusCode{
						Class:       1,
						Subject:     1,
						Detail:      7,
						Description: "Invalid DID format",
						Timestamp:   time.Now().UnixMilli(),
						Address:     fromDID.String(),
					},
				})
				continue
			}
			if err == types.ErrConflict {
				notFound = append(notFound, &types.DIDLookup{
					SupportsMailio: true,
					DIDDocument:    didDoc,
					MTPStatusCode: &types.MTPStatusCode{
						Class:       4,
						Subject:     4,
						Detail:      5,
						Description: "Rate limit exceeded on destination server",
						Timestamp:   time.Now().UnixMilli(),
						Address:     fromDID.String(),
					},
				})
				continue
			}
			if err == types.ErrBadRequest {
				notFound = append(notFound, &types.DIDLookup{
					SupportsMailio: true,
					DIDDocument:    didDoc,
					MTPStatusCode: &types.MTPStatusCode{
						Class:       4,
						Subject:     4,
						Detail:      0,
						Description: "Invalid DID resolution",
						Timestamp:   time.Now().UnixMilli(),
						Address:     fromDID.String(),
					},
				})
				continue
			}
			notFound = append(notFound, &types.DIDLookup{
				SupportsMailio: false,
				DIDDocument:    didDoc,
				MTPStatusCode: &types.MTPStatusCode{
					Class:       4,
					Subject:     4,
					Detail:      0,
					Description: "Server error",
					Timestamp:   time.Now().UnixMilli(),
					Address:     fromDID.String(),
				},
			})
		}
		found = append(found, &types.DIDLookup{
			SupportsMailio: true,
			DIDDocument:    didDoc,
			MTPStatusCode: &types.MTPStatusCode{
				Class:       2,
				Subject:     0,
				Detail:      0,
				Description: "DID found",
				Timestamp:   time.Now().UnixMilli(),
				Address:     fromDID.String(),
			},
		})
	}
	outputDIDLookup := &types.OutputDIDLookup{
		Found:    found,
		NotFound: notFound,
	}

	c.JSON(http.StatusOK, outputDIDLookup)
}
