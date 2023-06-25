package interceptors

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/go-jose/go-jose/v3"
)

func JWSMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		auth := c.GetHeader("Authorization")
		if auth == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Authorization header is missing"})
			return
		}

		// Load public key
		pemData, err := ioutil.ReadFile("path/to/public-key.pem")
		if err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to read public key"})
			return
		}

		block, _ := pem.Decode(pemData)
		if block == nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse public key"})
			return
		}

		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse public key"})
			return
		}

		publicKey, ok := pub.(ed25519.PublicKey)
		if !ok {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Invalid public key type"})
			return
		}

		// Parse JWS message
		object, err := jose.ParseSigned(auth)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid JWS message"})
			return
		}

		// Verify the signature
		output, err := object.Verify(publicKey)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Failed to verify JWS message"})
			return
		}

		// You may want to unmarshal and set the payload to the context
		fmt.Println("Payload:", string(output))
		c.Next()
	}
}
