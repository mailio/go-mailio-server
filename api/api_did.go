package api

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
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
	validate   *validator.Validate
}

func NewDIDApi(ssiService *services.SelfSovereignService) *DIDApi {
	return &DIDApi{
		ssiService: ssiService,
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

	domain := util.GetHostFromRequest(*c.Request)

	didDoc, err := util.CreateMailioDIDDocument(domain)
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

	domain := util.GetHostFromRequest(*c.Request)
	if _, ok := global.MailioDIDByDomain[domain]; !ok {
		ApiErrorf(c, http.StatusInternalServerError, "error creating server did configuration")
		return
	}
	mailioDID := global.MailioDIDByDomain[domain]

	if _, ok := global.MailioKeysCreatedByDomain[domain]; !ok {
		ApiErrorf(c, http.StatusInternalServerError, "error creating server did configuration (key creation date)")
		return
	}
	mailioKeysCreated := global.MailioKeysCreatedByDomain[domain]

	if _, ok := global.PrivateKeysByDomain[domain]; !ok {
		ApiErrorf(c, http.StatusInternalServerError, "error creating server did configuration (private key)")
		return
	}
	privateKey := global.PrivateKeysByDomain[domain]

	vc := did.NewVerifiableCredential(mailioDID.String())
	vc.Context = []string{"https://www.w3.org/2018/credentials/v1",
		"https://identity.foundation/.well-known/did-configuration/v1"}
	vc.Issuer = mailioDID.String()
	vc.IssuanceDate = time.UnixMilli(mailioKeysCreated)
	vc.Type = []string{"VerifiableCredential", "DomainLinkageCredential"}
	vc.CredentialSubject = did.CredentialSubject{
		ID:     mailioDID.String(),
		Origin: fmt.Sprintf("https://%s", domain),
	}

	// JWT version of the above proof as an alternative format
	jwtToken, jwtErr := jwt.NewBuilder().
		Issuer(mailioDID.String()).
		Subject(mailioDID.String()).
		NotBefore(time.Now().UTC()).
		Build()
	if jwtErr != nil {
		ApiErrorf(c, http.StatusInternalServerError, "error creating jwt: %s", jwtErr)
		return
	}

	jwtToken.Set("vc", vc)
	jwtSigned, jwtErr := jwt.Sign(jwtToken, jwt.WithKey(jwa.EdDSA, privateKey))
	if jwtErr != nil {
		ApiErrorf(c, http.StatusInternalServerError, "error signing jwt: %s", jwtErr)
		return
	}

	// proof section
	pErr := vc.CreateProof(privateKey)
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
