package interceptors

import (
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-jose/go-jose/v3"
	"github.com/mailio/go-mailio-server/global"
	"github.com/mailio/go-mailio-server/services"
	"github.com/mailio/go-mailio-server/types"
)

const (
	tokenExpiryHours = 30 * 24 // 30 days
)

func JWSMiddleware(userProfileService *services.UserProfileService) gin.HandlerFunc {
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
		subjectAddress := ""
		if sub, ok := plMap["sub"]; ok {
			addr := sub.(string)
			subjectAddress = strings.Replace(addr, "did:mailio:", "", 1)
		} else {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Failed to parse JWS payload (sub missing)"})
		}
		if usrPubKey, ok := plMap["usrPubKey"]; ok {
			usrPubKeyStr := usrPubKey.(string)
			c.Set("usrPubKey", usrPubKeyStr) // base64 encoded users public key
		} else {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Failed to parse JWS payload (usrPubKey missing)"})
		}
		// get user profile
		userProfile, upErr := userProfileService.Get(subjectAddress)
		if upErr != nil && upErr != types.ErrNotFound {
			global.Logger.Log("JWSMiddleware", "failed to get user profile", upErr.Error())
		}
		// user profile doesn't need to exist, unless user is disabled or has a subscription
		if userProfile != nil {
			if !userProfile.Enabled {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "User account is disabled"})
				return
			}
		} else {
			// add user profile into DB and into cache (for subsequent requests)
			userProfile = &types.UserProfile{Enabled: true, DiskSpace: global.Conf.Mailio.DiskSpace}
			userProfileService.Save(subjectAddress, userProfile)
		}
		c.Set("userProfile", userProfile)
		// TODO! subjectAddress is probably not necessary anymore since we have _id from userProfile
		c.Set("subjectAddress", subjectAddress)
		c.Next()
	}
}

func GenerateJWSToken(serverPrivateKey ed25519.PrivateKey, userDid, challenge, userPublicKeyEd25519 string) (string, error) {
	pl := map[string]interface{}{
		"iss":       global.MailioDID.String(),
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
