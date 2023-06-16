package api

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/mail"

	"github.com/gin-gonic/gin"
	"github.com/go-jose/go-jose/v3"
	"github.com/go-playground/validator/v10"
	"github.com/mailio/go-mailio-server/global"
	"github.com/mailio/go-mailio-server/services"
	"github.com/mailio/go-mailio-server/types"
	"github.com/mailio/go-mailio-server/util"
)

type UserAccountApi struct {
	userService *services.UserService
	validate    *validator.Validate
}

func NewUserAccountApi(userService *services.UserService) *UserAccountApi {
	return &UserAccountApi{
		userService: userService,
		validate:    validator.New(),
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

	var inputRegister types.InputRegister
	if err := c.ShouldBindJSON(&inputRegister); err != nil {
		ApiErrorf(c, http.StatusBadRequest, "invalid email or password")
		return
	}

	err := ua.validate.Struct(inputRegister)
	if err != nil {
		msg := ValidatorErrorToUser(err.(validator.ValidationErrors))
		ApiErrorf(c, http.StatusBadRequest, msg)
		return
	}

	emailAddr, err := mail.ParseAddress(inputRegister.Email)
	if err != nil {
		ApiErrorf(c, http.StatusBadRequest, "invalid email address")
		return
	}

	scryptedEmail, sErr := util.ScryptEmail(emailAddr.Address)
	if sErr != nil {
		ApiErrorf(c, http.StatusInternalServerError, "Failed to scrypt email")
		return
	}

	user := &types.User{
		Email:          emailAddr.Address,
		EncryptedEmail: base64.StdEncoding.EncodeToString(scryptedEmail),
		Address:        inputRegister.Address,
		Created:        util.GetTimestamp(),
	}
	output, err := ua.userService.CreateUser(user, inputRegister.Password)
	if err != nil {
		ApiErrorf(c, http.StatusBadRequest, err.Error())
		return
	}

	token, tErr := generateJWSToken(global.PrivateKey, []byte(output.Email))
	if tErr != nil {
		ApiErrorf(c, http.StatusInternalServerError, "Failed to sign token")
		return
	}

	c.JSON(http.StatusOK, gin.H{"token": token})
}
