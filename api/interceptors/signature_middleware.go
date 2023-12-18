package interceptors

import (
	"encoding/base64"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
	"github.com/go-kit/log/level"
	"github.com/go-playground/validator/v10"
	"github.com/mailio/go-mailio-server/global"
	"github.com/mailio/go-mailio-server/types"
	"github.com/mailio/go-mailio-server/util"
	"golang.org/x/net/idna"
)

var validate = validator.New()

// validating signatures of incoming requests
func SignatureMiddleware(env *types.Environment) gin.HandlerFunc {
	return func(c *gin.Context) {
		var commonSignature types.CommonSignature
		if err := c.ShouldBindBodyWith(&commonSignature, binding.JSON); err != nil {
			level.Error(global.Logger).Log("invalid structure", err.Error())
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
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
		domain := commonSignature.SenderDomain
		host, err := idna.Lookup.ToASCII(domain)
		if err != nil {
			level.Error(global.Logger).Log("invalid domain", err.Error())
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid domain"})
			c.Abort()
			return
		}
		// DNS check the host for (extracting the public key)
		pk, pkErr := util.GetDNSMailioPublicKey(host)
		if pkErr != nil {
			level.Error(global.Logger).Log("no Mailio DNS record", err.Error())
			c.JSON(http.StatusBadRequest, gin.H{"error": "no Mailio DNS record found"})
			c.Abort()
			return
		}
		cborPayload, _ := base64.StdEncoding.DecodeString(commonSignature.CborPayloadBase64)
		signature, _ := base64.StdEncoding.DecodeString(commonSignature.SignatureBase64)
		isValid, sigErr := env.MailioCrypto.Verify(cborPayload, signature, pk)
		if sigErr != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "signature verification failed"})
			c.Abort()
			return
		}
		if !isValid {
			c.JSON(http.StatusBadRequest, gin.H{"error": "signature verification failed"})
			c.Abort()
			return
		}
		c.Set("data", commonSignature)
		c.Next()
	}
}
