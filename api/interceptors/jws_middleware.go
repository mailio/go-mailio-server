package interceptors

import (
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-jose/go-jose/v3"
	"github.com/mailio/go-mailio-server/global"
)

const (
	tokenExpiryHours = 30 * 24 // 30 days
)

func JWSMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		auth := c.GetHeader("Authorization")
		if auth == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Authorization header is missing"})
			return
		}

		// Parse JWS message
		object, err := jose.ParseSigned(auth)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid JWS message"})
			return
		}

		// Verify the signature
		_, err = object.Verify(global.PublicKey)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Failed to verify JWS message"})
			return
		}
		payload := object.UnsafePayloadWithoutVerification()
		var plMap map[string]interface{}
		uErr := json.Unmarshal(payload, &plMap)
		if uErr != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Failed to parse JWS payload"})
			return
		}
		if exp, ok := plMap["exp"]; ok {
			expInt, ok := exp.(float64)
			if !ok {
				c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Failed to parse JWS payload"})
				return
			}
			if float64(expInt) < float64((int32)((int32)(time.Now().Unix()))) {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "JWS message expired"})
				return
			}
		} else {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Failed to parse JWS payload (exp missing)"})
			return
		}
		c.Next()
	}
}

func GenerateJWSToken(serverPrivateKey ed25519.PrivateKey, userDid, challenge string) (string, error) {
	pl := map[string]interface{}{
		"iss": global.MailioDID.String(),
		"sub": userDid,
		"iat": time.Now().Unix(),
		"jti": challenge,
		"exp": time.Now().Add(time.Hour * tokenExpiryHours).Unix(),
		"aud": "mailio",
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: serverPrivateKey}, nil)
	if err != nil {
		return "", err
	}

	plBytes, plErr := json.Marshal(pl)
	if plErr != nil {
		return "", plErr
	}
	object, err := signer.Sign(plBytes)
	if err != nil {
		return "", err
	}

	return object.CompactSerialize()
}
