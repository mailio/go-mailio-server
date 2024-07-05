package api

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/mailio/go-mailio-did/did"
	"github.com/mailio/go-mailio-server/api/interceptors"
	apiutil "github.com/mailio/go-mailio-server/api/util"
	"github.com/mailio/go-mailio-server/global"
)

// set cookie in the response (httpOnly)
func setCookieAndGenerateToken(c *gin.Context, userDID *did.MailioKey, challenge string, usersPrimaryEd25519PublicKey string) (string, error) {
	token, tErr := interceptors.GenerateJWSToken(global.PrivateKey, userDID.DID(), global.MailioDID, challenge, usersPrimaryEd25519PublicKey)
	if tErr != nil {
		return "", tErr
	}

	domain, dErr := apiutil.GetIPFromContext(c)
	if dErr != nil {
		d := "localhost"
		domain = &d
	}
	secure := true
	if strings.Contains(*domain, "localhost") || strings.Contains(*domain, "::1") || strings.Contains(*domain, "127.0.0.1") {
		secure = false
		d := "localhost"
		domain = &d
	}

	cookie := http.Cookie{
		Name:     "__mailio-jws-token",
		Value:    token,
		Expires:  time.Now().Add(24 * 60 * time.Hour), // 60 days
		Path:     "/",
		Domain:   "localhost",
		Secure:   secure,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}

	http.SetCookie(c.Writer, &cookie)

	return token, nil
}
