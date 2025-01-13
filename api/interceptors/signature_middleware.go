package interceptors

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/go-kit/log/level"
	"github.com/go-playground/validator/v10"
	"github.com/mailio/go-mailio-server/global"
	"github.com/mailio/go-mailio-server/services"
	"github.com/mailio/go-mailio-server/types"
	"github.com/mailio/go-mailio-server/util"
	"golang.org/x/net/idna"
)

var validate = validator.New()

// validating signatures of incoming requests
func SignatureMiddleware(env *types.Environment, mtpService *services.MtpService) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Create a copy of the request body
		bodyBytes, cpBodyErr := io.ReadAll(c.Request.Body)
		if cpBodyErr != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to read request body"})
			c.Abort()
			return
		}
		// Restore the request body for downstream handlers
		c.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

		var commonSignature types.CommonSignature
		if csErr := json.Unmarshal(bodyBytes, &commonSignature); csErr != nil {
			global.Logger.Log("error unmarshalling request body", csErr.Error())
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
			c.Abort()
			return
		}

		err := validate.Struct(commonSignature)
		if err != nil {
			msg := util.ValidationErrorToMessage(err)
			level.Error(global.Logger).Log("bad request", msg)
			c.JSON(http.StatusBadRequest, gin.H{"error": msg})
			c.Abort()
			return
		}
		// IDNA encode the domain
		host := commonSignature.SenderDomain
		if !strings.Contains(host, "localhost") {
			h, err := idna.Lookup.ToASCII(host)
			if err != nil {
				level.Error(global.Logger).Log("invalid domain", err.Error())
				c.JSON(http.StatusBadRequest, gin.H{"error": "invalid domain"})
				c.Abort()
				return
			}
			host = h
		}
		// DNS check the host for (extracting the public key)
		//TODO: handle localhost
		resolvedDomain := &types.Domain{
			SupportsMailio:  true,
			MailioPublicKey: base64.StdEncoding.EncodeToString(global.PublicKey),
			Name:            host,
			Timestamp:       0,
		}
		if !strings.Contains(host, "localhost") {
			rd, dErr := mtpService.ResolveDomain(host, false)
			if dErr != nil {
				level.Error(global.Logger).Log("no Mailio DNS record", dErr.Error())
				c.JSON(http.StatusBadRequest, gin.H{"error": "no Mailio DNS record found"})
				c.Abort()
				return
			}
			resolvedDomain = rd
		}

		cborPayload, _ := base64.StdEncoding.DecodeString(commonSignature.CborPayloadBase64)
		signature, _ := base64.StdEncoding.DecodeString(commonSignature.SignatureBase64)
		isValid, sigErr := util.Verify(cborPayload, signature, resolvedDomain.MailioPublicKey)
		if sigErr != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "signature verification failed"})
			c.Abort()
			return
		}
		if !isValid {
			// re-check online for the public key (in case it changed). Force DNS discovery
			resolvedDomain, dErr := mtpService.ResolveDomain(host, true)
			if dErr != nil {
				level.Error(global.Logger).Log("no Mailio DNS record", err.Error())
				c.JSON(http.StatusBadRequest, gin.H{"error": "no Mailio DNS record found"})
				c.Abort()
				return
			}
			secondVerify, secondSigErr := util.Verify(cborPayload, signature, resolvedDomain.MailioPublicKey)
			if secondSigErr != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "signature verification failed"})
				c.Abort()
				return
			}
			if !secondVerify {
				c.JSON(http.StatusBadRequest, gin.H{"error": "signature verification failed"})
				c.Abort()
				return
			}
		}
		c.Set("data", commonSignature)
		c.Next()
	}
}
