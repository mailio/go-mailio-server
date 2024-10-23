package interceptors

import (
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-jose/go-jose/v3"
	"github.com/mailio/go-mailio-did/did"
	"github.com/mailio/go-mailio-server/global"
	"github.com/mailio/go-mailio-server/services"
)

const (
	tokenExpiryHours = 30 * 24 // 30 days
)

func JWSMiddleware(userProfileService *services.UserProfileService) gin.HandlerFunc {
	return func(c *gin.Context) {
		auth := c.GetHeader("Authorization")
		if auth == "" {
			// check cookies for __mailio-jws-token
			cookie, err := c.Request.Cookie("__mailio-jws-token")
			if err == nil {
				auth = cookie.Value
			}
			if auth == "" {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Authorization header is missing"})
				return
			}
		}

		// Parse JWS message
		object, err := jose.ParseSigned(auth)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid JWS message"})
			return
		}

		payload := object.UnsafePayloadWithoutVerification()
		var plMap map[string]interface{}
		uErr := json.Unmarshal(payload, &plMap)
		if uErr != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Failed to parse JWS payload"})
			return
		}

		subjectAddress := ""
		if sub, ok := plMap["sub"]; ok {
			addr := sub.(string)
			subjectAddress = strings.Replace(addr, "did:mailio:", "", 1)
		} else {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Failed to parse JWS payload (sub missing)"})
		}
		// get user profile
		userProfile, upErr := userProfileService.Get(subjectAddress)
		if upErr != nil {
			global.Logger.Log("JWSMiddleware", "failed to find user profile", upErr.Error())
		}
		if userProfile == nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "User account not found"})
			return
		}
		// check if user is enabled
		if !userProfile.Enabled {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "User account is disabled"})
			return
		}

		// Verify the signature
		_, err = object.Verify(global.PublicKey)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Failed to verify JWS message"})
			return
		}

		if usrPubKey, ok := plMap["usrPubKey"]; ok {
			usrPubKeyStr := usrPubKey.(string)
			c.Set("usrPubKey", usrPubKeyStr) // base64 encoded users public key
		} else {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Failed to parse JWS payload (usrPubKey missing)"})
		}

		c.Set("userProfile", userProfile)
		// TODO! subjectAddress is probably not necessary anymore since we have _id from userProfile
		c.Set("subjectAddress", subjectAddress)
		c.Next()
	}
}

func GenerateJWSToken(serverPrivateKey ed25519.PrivateKey, userDid string, mailioDID *did.DID, challenge, userPublicKeyEd25519 string) (string, error) {
	pl := map[string]interface{}{
		"iss":       mailioDID.String(),
		"sub":       userDid,
		"iat":       time.Now().Unix(),
		"jti":       challenge,
		"exp":       time.Now().Add(time.Hour * tokenExpiryHours).Unix(),
		"aud":       "mailio",
		"usrPubKey": userPublicKeyEd25519,
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
