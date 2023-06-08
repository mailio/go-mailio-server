package api

import (
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/mail"

	"github.com/gin-gonic/gin"
	"github.com/go-jose/go-jose/v3"
	"github.com/go-playground/validator/v10"
	"github.com/mailio/go-mailio-server/repository"
	"github.com/mailio/go-mailio-server/types"
	"github.com/mailio/go-mailio-server/util"
)

type UserAccountApi struct {
	repo     repository.Repository
	validate *validator.Validate
}

func NewUserAccountApi(repo repository.Repository) *UserAccountApi {
	return &UserAccountApi{
		repo:     repo,
		validate: validator.New(),
	}
}

func generateJWSToken(privateKey ed25519.PrivateKey, payload []byte) (string, error) {
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: privateKey}, nil)
	if err != nil {
		return "", err
	}

	object, err := signer.Sign(payload)
	if err != nil {
		return "", err
	}

	return object.CompactSerialize()
}

// Login method
// @Summary Login with username and password
// @Description Returns a JWS token
// @Tags USER ACCOUNT API
// @Param id path string true "Handshake ID"
// @Success 200 {object} types.JwsToken
// @Accept json
// @Produce json
// @Router /api/v1/login [post]
func (ua *UserAccountApi) Login(c *gin.Context) {
	// Create a payload with the user's ID and the token's expiration time.
	// Replace "userID" and "expirationTime" with your actual user ID and token expiration time.
	payload, err := json.Marshal(map[string]interface{}{
		"sub": "userID",
		"exp": "expirationTime",
	})
	if err != nil {
		ApiErrorf(c, http.StatusInternalServerError, "Failed to create token payload")
		return
	}

	var privateKey ed25519.PrivateKey
	//TODO! load privat key from server keys

	// Sign the payload with servers private key.
	// Replace "privateKey" with your actual private key.
	token, err := generateJWSToken(privateKey, payload)
	if err != nil {
		ApiErrorf(c, http.StatusInternalServerError, "Failed to sign token")
		return
	}

	// Send the token back to the client.
	c.JSON(http.StatusOK, gin.H{"token": token})
}

// Register user method
// @Summary Register user
// @Description Returns a JWS token
// @Tags USER ACCOUNT API
// @Param emailPassword body types.InputEmailPassword true "email and password input"
// @Success 200 {object} types.JwsToken
// @Accept json
// @Produce json
// @Router /api/v1/register [post]
func (ua *UserAccountApi) Register(c *gin.Context) {

	var emailPassword types.InputEmailPassword
	if err := c.ShouldBindJSON(&emailPassword); err != nil {
		ApiErrorf(c, http.StatusBadRequest, "invalid email or password")
		return
	}

	err := ua.validate.Struct(emailPassword)
	if err != nil {
		msg := ValidatorErrorToUser(err.(validator.ValidationErrors))
		ApiErrorf(c, http.StatusBadRequest, msg)
		return
	}

	emailAddr, err := mail.ParseAddress(emailPassword.Email)
	if err != nil {
		ApiErrorf(c, http.StatusBadRequest, "invalid email address")
		return
	}
	// resp, err := c.restClient.R().SetBody(map[string]interface{}{"name": user, "password": password, "roles": []string{}, "type": "user"}).Put(fmt.Sprintf("/_users/org.couchdb.user:%s", user))
	// if err != nil {
	// 	global.Logger.Log(err, "Failed to register user")
	// 	return nil, err
	// }
	hexUser := "userdb-" + util.HexEncodeToString(emailAddr.Address)

	c.JSON(http.StatusOK, gin.H{"token": hexUser})
}
