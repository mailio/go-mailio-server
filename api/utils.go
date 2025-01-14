package api

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/mailio/go-mailio-did/did"
	"github.com/mailio/go-mailio-server/api/interceptors"
	"github.com/mailio/go-mailio-server/global"
)

// set cookie in the response (httpOnly)
func setCookieAndGenerateToken(c *gin.Context, userDID *did.MailioKey, challenge string, usersPrimaryEd25519PublicKey string) (string, error) {
	token, tErr := interceptors.GenerateJWSToken(global.PrivateKey, userDID.DID(), global.MailioDID, challenge, usersPrimaryEd25519PublicKey)
	if tErr != nil {
		return "", tErr
	}
	domain := global.Conf.Mailio.ServerDomain
	secure := true
	if strings.Contains(domain, "localhost") || strings.Contains(domain, "::1") || strings.Contains(domain, "127.0.0.1") {
		secure = false
		domain = "localhost"
	}

	cookie := http.Cookie{
		Name:     "__mailio-jws-token",
		Value:    token,
		Expires:  time.Now().Add(24 * 29 * time.Hour), // 29 days
		MaxAge:   24 * 29 * 60 * 60,
		Path:     "/",
		Domain:   "." + domain,
		Secure:   secure,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}

	http.SetCookie(c.Writer, &cookie)

	return token, nil
}
