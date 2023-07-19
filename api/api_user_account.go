package api

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/mail"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-jose/go-jose/v3"
	"github.com/go-playground/validator/v10"
	mailiocrypto "github.com/mailio/go-mailio-core/crypto"
	"github.com/mailio/go-mailio-core/did"
	coreErrors "github.com/mailio/go-mailio-core/errors"
	"github.com/mailio/go-mailio-server/global"
	"github.com/mailio/go-mailio-server/services"
	"github.com/mailio/go-mailio-server/types"
	"github.com/mailio/go-mailio-server/util"
)

type UserAccountApi struct {
	userService  *services.UserService
	nonceService *services.NonceService
	ssiService   *services.SelfSovereignService
	validate     *validator.Validate
}

func NewUserAccountApi(userService *services.UserService, nonceService *services.NonceService, ssiService *services.SelfSovereignService) *UserAccountApi {
	return &UserAccountApi{
		userService:  userService,
		nonceService: nonceService,
		ssiService:   ssiService,
		validate:     validator.New(),
	}
}

func generateJWSToken(serverPrivateKey ed25519.PrivateKey, userDid, challenge string) (string, error) {
	pl := map[string]interface{}{
		"iss": global.MailioDID.String(),
		"sub": userDid,
		"iat": time.Now().Unix(),
		"jti": challenge,
		"exp": time.Now().Add(time.Minute * 5).Unix(),
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

// Validate signature from the input data
func validateSignature(loginInput *types.InputLogin) (bool, error) {
	//TODO! important! validate that nonce came from the server
	if !util.IsEd25519PublicKey(loginInput.Ed25519SigningPublicKeyBase64) {
		return false, coreErrors.ErrInvalidPublicKey
	}
	signingKeyBytes, _ := base64.StdEncoding.DecodeString(loginInput.Ed25519SigningPublicKeyBase64)

	signatureBytes, sErr := base64.StdEncoding.DecodeString(loginInput.SignatureBase64)
	if sErr != nil {
		return false, coreErrors.ErrSignatureInvalid
	}

	// verify signature
	isValid := ed25519.Verify(signingKeyBytes, []byte(loginInput.Nonce), signatureBytes)
	return isValid, nil
}

// Login and Registration challenge nonce
// @Summary Login and Registration challenge nonce
// @Description Returns a nonce which client needs to sign with their private key
// @Tags User Account
// @Success 200 {object} types.NonceResponse
// @Accept json
// @Produce json
// @Router /api/v1/nonce [get]
func (ua *UserAccountApi) ChallengeNonce(c *gin.Context) {
	nonce64Bytes, err := util.GenerateNonce(64)
	if err != nil {
		ApiErrorf(c, http.StatusInternalServerError, "Failed to generate nonce: %v", err)
		return
	}
	nonce := types.NonceResponse{
		Nonce: nonce64Bytes,
	}
	//TODO! store nonce to the couchdb and expire it after N minutes
	c.JSON(http.StatusOK, nonce)
}

// Login method
// @Summary Login with username and password
// @Description Returns a JWS token
// @Tags User Account
// @Param nonce query string true "Nonce string"
// @Success 200 {object} types.JwsToken
// @Accept json
// @Produce json
// @Router /api/v1/login [post]
func (ua *UserAccountApi) Login(c *gin.Context) {
	// Create a payload with the user's ID and the token's expiration time.
	// Replace "userID" and "expirationTime" with your actual user ID and token expiration time.
	var inputLogin types.InputLogin
	if err := c.ShouldBindJSON(&inputLogin); err != nil {
		ApiErrorf(c, http.StatusBadRequest, "invalid email or password")
		return
	}
	if !util.IsEd25519PublicKey(inputLogin.Ed25519SigningPublicKeyBase64) {
		ApiErrorf(c, http.StatusBadRequest, "invalid public key")
		return
	}
	decodedPubKey, _ := base64.StdEncoding.DecodeString(inputLogin.Ed25519SigningPublicKeyBase64)
	pubKey := ed25519.PublicKey(decodedPubKey)
	mk := did.MailioKey{
		MasterSignKey: &did.Key{
			PublicKey: pubKey,
		},
	}

	// // get user by email
	// if inputUserPass.PublicKeyBase64 == "" || inputUserPass.SignatureBase64 == "" {
	// 	ApiErrorf(c, http.StatusBadRequest, "public key and signature are required")
	// 	return
	// }
	// if util.IsEd25519PublicKey(inputUserPass.PublicKeyBase64) == false {
	// 	ApiErrorf(c, http.StatusBadRequest, "invalid public key")
	// 	return
	// }
	// decodedPubKey, _ := base64.StdEncoding.DecodeString(inputUserPass.PublicKeyBase64)
	// decodedSignature, err := base64.StdEncoding.DecodeString(inputUserPass.SignatureBase64)
	// if err != nil {
	// 	ApiErrorf(c, http.StatusBadRequest, "invalid signature")
	// 	return
	// }
	// userPk := ed25519.PublicKey(decodedPubKey)
	// // Verify the signature of the token using the user's public key.
	// isValidSignature := ed25519.Verify(userPk, []byte(inputUserPass.Nonce), decodedSignature)
	// if !isValidSignature {
	// 	ApiErrorf(c, http.StatusBadRequest, "invalid signature")
	// 	return
	// }
	// Sign the payload with servers private key.
	token, err := generateJWSToken(global.PrivateKey, mk.DID(), inputLogin.Nonce)
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
// @Tags User Account
// @Param registration body types.InputRegister true "registration input"
// @Success 200 {object} types.JwsToken
// @Failure 404 {object} ApiError "Invalid input parameters"
// @Failure 500 {object} ApiError "Internal server error"
// @Failure 409 {object} ApiError "User already exists"
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

	// validation methods (email, signature, public key)
	emailAddr, err := mail.ParseAddress(inputRegister.Email)
	if err != nil {
		ApiErrorf(c, http.StatusBadRequest, "invalid email address")
		return
	}
	if !util.IsEd25519PublicKey(inputRegister.X25519PublicKeyBase64) {
		ApiErrorf(c, http.StatusBadRequest, "invalid encryption public key")
		return
	}
	signingKeyBytes, skBytesErr := base64.StdEncoding.DecodeString(inputRegister.Ed25519SigningPublicKeyBase64)
	if skBytesErr != nil {
		ApiErrorf(c, http.StatusBadRequest, "invalid signing public key")
		return
	}
	signingKey := ed25519.PublicKey(signingKeyBytes)
	encryptionKeyBytes, ekBytesErr := base64.StdEncoding.DecodeString(inputRegister.X25519PublicKeyBase64)
	if ekBytesErr != nil {
		ApiErrorf(c, http.StatusBadRequest, "invalid encryption public key")
		return
	}
	encryptionPublicKey := ed25519.PublicKey(encryptionKeyBytes)

	// validate siganture
	isValid, validErr := validateSignature(&inputRegister.InputLogin)
	if validErr != nil {
		if validErr == coreErrors.ErrSignatureInvalid {
			ApiErrorf(c, http.StatusBadRequest, "invalid signature")
			return
		} else if validErr == coreErrors.ErrInvalidPublicKey {
			ApiErrorf(c, http.StatusBadRequest, "invalid public key")
			return
		}
		ApiErrorf(c, http.StatusInternalServerError, "failed to validate signature")
		return
	}
	if !isValid {
		ApiErrorf(c, http.StatusBadRequest, "invalid signature")
		return
	}

	mailioAddress, err := mailiocrypto.NewMailioCrypto().PublicKeyToMailioAddress(inputRegister.Ed25519SigningPublicKeyBase64)
	if err != nil {
		ApiErrorf(c, http.StatusInternalServerError, "failed to generate mailio address")
		return
	}
	// validate mailio address format
	if inputRegister.MailioAddress != *mailioAddress {
		ApiErrorf(c, http.StatusBadRequest, "invalid mailio address")
		return
	}

	// if everything checks out, create users database, DID document and Verifiable Credential of owning the email address
	// then store all to database
	scryptedEmail, sErr := util.ScryptEmail(emailAddr.Address)
	if sErr != nil {
		ApiErrorf(c, http.StatusInternalServerError, "Failed to scrypt email")
		return
	}

	user := &types.User{
		Email:          emailAddr.Address,
		EncryptedEmail: base64.StdEncoding.EncodeToString(scryptedEmail),
		MailioAddress:  inputRegister.MailioAddress,
		Created:        util.GetTimestamp(),
	}
	// create user database
	_, errCU := ua.userService.CreateUser(user, inputRegister.DatabasePassword)
	if errCU != nil {
		if errCU == coreErrors.ErrUserExists {
			ApiErrorf(c, http.StatusConflict, "user already exists")
			return
		}
		if errCU == types.ErrConflict {
			ApiErrorf(c, http.StatusConflict, "user already exists")
			return
		}
		ApiErrorf(c, http.StatusBadRequest, errCU.Error())
		return
	}

	// map sacrypt (encrryped email) address to mailio address
	_, errMu := ua.userService.MapEmailToMailioAddress(user)
	if errMu != nil {
		if errMu == coreErrors.ErrUserExists {
			ApiErrorf(c, http.StatusBadRequest, "user already exists")
			return
		}
		ApiErrorf(c, http.StatusInternalServerError, "failed to create user to address mapping")
		return
	}

	// create DID ID and DID document and store it in database!
	mk := &did.MailioKey{
		MasterSignKey: &did.Key{
			Type:      did.KeyTypeEd25519,
			PublicKey: signingKey,
		},
		MasterAgreementKey: &did.Key{
			Type:      did.KeyTypeX25519KeyAgreement,
			PublicKey: encryptionPublicKey,
		},
	}
	ssiErr := ua.ssiService.StoreRegistrationSSI(mk)
	if ssiErr != nil {
		ApiErrorf(c, http.StatusInternalServerError, "failed to store self-sovereign identity")
		return
	}

	token, tErr := generateJWSToken(global.PrivateKey, mk.DID(), inputRegister.Nonce)
	if tErr != nil {
		ApiErrorf(c, http.StatusInternalServerError, "Failed to sign token")
		return
	}

	c.JSON(http.StatusOK, gin.H{"token": token})
}

// Find user by email address
// @Summary Find user by base64 scrypt email address
// @Description Returns a mailio address
// @Tags User Account
// @Param email query string true "Base64 formatted Scrypt of email address"
// @Success 200 {object} types.OutputFindAddress
// @Accept json
// @Produce json
// @Router /api/v1/findaddress [get]
func (ua *UserAccountApi) FindUsersAddressByEmail(c *gin.Context) {
	email := c.Query("email")
	if email == "" {
		ApiErrorf(c, http.StatusBadRequest, "scrypt of email is require with params: N=32768, R=8,P=1,Len=32")
		return
	}

	mapping, err := ua.userService.FindUserByScryptEmail(email)
	if err != nil {
		ApiErrorf(c, http.StatusNotFound, "email not found")
		return
	}
	output := &types.OutputFindAddress{
		Address: mapping.MailioAddress,
	}
	c.JSON(http.StatusOK, output)
}
