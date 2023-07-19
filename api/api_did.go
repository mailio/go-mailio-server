package api

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/mailio/go-mailio-core/did"
	"github.com/mailio/go-mailio-server/global"
	"github.com/mailio/go-mailio-server/util"
)

type DIDApi struct {
}

func NewDIDApi() *DIDApi {
	return &DIDApi{}
}

// Server DID
// @Summary Mailio Server DID Document (public keys)
// @Description Returns a DID Document
// @Tags Decentralized Identifiers
// @Success 200 {object} did.Document
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
		Origin: "https://mail.io",
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
// @Summary Return users DID document
// @Description Returns users DID document based on mailio address
// @Tags Decentralized Identifiers
// @Accept json
// @Produce json
// @Router /v1/{address}/did.json [get]
func (did *DIDApi) GetUserDID(c *gin.Context) {
	//TODO! finish implementation
	c.JSON(http.StatusOK, gin.H{"message": "not implemented"})
}
