package api

import (
	"crypto/ed25519"
	"encoding/base64"
	"net/http"
	"net/mail"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"github.com/mailio/go-mailio-did/did"
	diskusagehandlers "github.com/mailio/go-mailio-diskusage-handler"
	"github.com/mailio/go-mailio-server/api/interceptors"
	apiutil "github.com/mailio/go-mailio-server/api/util"
	"github.com/mailio/go-mailio-server/diskusage"
	"github.com/mailio/go-mailio-server/global"
	"github.com/mailio/go-mailio-server/services"
	"github.com/mailio/go-mailio-server/types"
	"github.com/mailio/go-mailio-server/util"
)

type UserAccountApi struct {
	userService        *services.UserService
	nonceService       *services.NonceService
	ssiService         *services.SelfSovereignService
	userProfileService *services.UserProfileService
	smartKeyService    *services.SmartKeyService
	validate           *validator.Validate
}

func NewUserAccountApi(userService *services.UserService, userProfileService *services.UserProfileService, nonceService *services.NonceService, ssiService *services.SelfSovereignService, smartKeyService *services.SmartKeyService) *UserAccountApi {
	return &UserAccountApi{
		userService:        userService,
		nonceService:       nonceService,
		ssiService:         ssiService,
		userProfileService: userProfileService,
		smartKeyService:    smartKeyService,
		validate:           validator.New(),
	}
}

// Login and Registration challenge nonce
// @Summary Login and Registration challenge nonce
// @Description Returns a nonce which client needs to sign with their private key
// @Tags User Account
// @Success 200 {object} types.NonceResponse
// @Failure 429 {object} api.ApiError "rate limit exceeded"
// @Failure 500 {object} api.ApiError "Internal server error"
// @Accept json
// @Produce json
// @Router /api/v1/nonce [get]
func (ua *UserAccountApi) ChallengeNonce(c *gin.Context) {
	// store nonce to the couchdb and expire it after N minutes
	nonce, err := ua.nonceService.CreateNonce()
	if err != nil {
		ApiErrorf(c, http.StatusInternalServerError, "Failed to generate nonce")
		return
	}
	c.JSON(http.StatusOK, nonce)
}

// Deletes nonce if it exists
// @Summary Deletes nonce if it exists
// @Description Deletes nonce if it exists
// @Tags User Account
// @Param id path string true "nonce id"
// @Success 200 {object} types.NonceResponse
// @Failure 404 {object} api.ApiError "not found"
// @Failure 429 {object} api.ApiError "rate limit exceeded"
// @Failure 500 {object} api.ApiError "Internal server error"
// @Accept json
// @Produce json
// @Router /api/v1/nonce/{id} [delete]
func (ua *UserAccountApi) DeleteNonce(c *gin.Context) {
	nonceId := c.Param("id")
	if nonceId == "" {
		ApiErrorf(c, http.StatusBadRequest, "nonce id is required")
		return
	}
	nonce, err := ua.nonceService.GetNonce(nonceId)
	if err != nil {
		if err == types.ErrNotFound {
			ApiErrorf(c, http.StatusNotFound, "nonce not found")
		} else {
			ApiErrorf(c, http.StatusInternalServerError, "Failed to retrieve nonce")
		}
		return
	}
	delErr := ua.nonceService.DeleteNonce(nonceId)
	if delErr != nil {
		ApiErrorf(c, http.StatusInternalServerError, "Failed to delete nonce")
		return
	}

	c.JSON(http.StatusOK, nonce)
}

// Login method
// @Summary Login with username and password
// @Description Returns a JWS token
// @Tags User Account
// @Param login body types.InputLogin true "login input"
// @Success 200 {object} types.JwsToken
// @Failure 401 {object} api.ApiError "Invalid signature"
// @Failure 403 {object} api.ApiError "Failed to login (valid signature, no valid VC)"
// @Failure 404 {object} api.ApiError "Failed to login (user not registered)"
// @Failure 400 {object} api.ApiError "Invalid or missing input parameters"
// @Failure 429 {object} api.ApiError "rate limit exceeded"
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
	if inputLogin.MailioAddress == "" || inputLogin.Nonce == "" || inputLogin.SignatureBase64 == "" {
		ApiErrorf(c, http.StatusBadRequest, "mailio address, nonce and signature are required")
		return
	}
	decodedPubKey, _ := base64.StdEncoding.DecodeString(inputLogin.Ed25519SigningPublicKeyBase64)
	pubKey := ed25519.PublicKey(decodedPubKey)
	mk := did.MailioKey{
		MasterSignKey: &did.Key{
			PublicKey: pubKey,
		},
	}

	// check if nonce exists and is not expired
	foundNonce, fnErr := ua.nonceService.GetNonce(inputLogin.Nonce)
	if fnErr != nil {
		ApiErrorf(c, http.StatusUnauthorized, "nonce not found")
		return
	}

	millisecondsNow := time.Now().UTC().UnixMilli() - int64(5*60*1000) // 5 mintes ago
	if foundNonce.Created < millisecondsNow {
		ApiErrorf(c, http.StatusUnauthorized, "nonce expired")
		return
	}

	validErr := apiutil.ValidateMailioKeys(inputLogin.MailioAddress, inputLogin.Ed25519SigningPublicKeyBase64, foundNonce.Nonce, inputLogin.MailioAddress)
	if validErr != nil {
		if validErr == types.ErrSignatureInvalid {
			ApiErrorf(c, http.StatusUnauthorized, "invalid signature")
			return
		} else if validErr == types.ErrInvalidPublicKey {
			ApiErrorf(c, http.StatusUnauthorized, "invalid public key")
			return
		} else if validErr == types.ErrNotFound {
			ApiErrorf(c, http.StatusUnauthorized, "nonce not found")
			return
		}
		ApiErrorf(c, http.StatusInternalServerError, "failed to validate signature")
		return
	}
	// delete nonce from database (don't fail if nonce not found)
	ua.nonceService.DeleteNonce(foundNonce.Nonce)

	// retrieve appropriate mailio DID by domain
	userProfile, upErr := ua.userProfileService.Get(inputLogin.MailioAddress)
	if upErr != nil {
		ApiErrorf(c, http.StatusNotFound, "user not found")
		return
	}
	// check if user is disabled!
	if !userProfile.Enabled {
		ApiErrorf(c, http.StatusForbidden, "user is disabled")
		return
	}

	// validate also VC for the user (proof that user was registered at host)
	vc, vcErr := ua.ssiService.GetAuthorizedAppVCByAddress(inputLogin.MailioAddress, global.MailioDID.String())
	if vcErr != nil {
		if vcErr == types.ErrNotFound {
			ApiErrorf(c, http.StatusNotFound, "user not found")
			return
		}
		ApiErrorf(c, http.StatusInternalServerError, "failed to retrieve a Verifiable Cred.")
		return
	}
	isVCValid, vcValidateErr := vc.VerifyProof(global.PublicKey)
	if vcValidateErr != nil {
		ApiErrorf(c, http.StatusForbidden, "user not registered at this host (failed proof validation)")
		return
	}
	if !isVCValid {
		ApiErrorf(c, http.StatusForbidden, "user not registered at this host (proof signature invalid)")
		return
	}

	// Sign the payload with servers private key.
	token, err := interceptors.GenerateJWSToken(global.PrivateKey, mk.DID(), global.MailioDID, inputLogin.Nonce, inputLogin.Ed25519SigningPublicKeyBase64)
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
// @Failure 401 {object} api.ApiError "Invalid signature"
// @Failure 404 {object} ApiError "Invalid input parameters"
// @Failure 409 {object} ApiError "User already exists"
// @Failure 429 {object} api.ApiError "rate limit exceeded"
// @Failure 500 {object} ApiError "Internal server error"
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

	// check if nonce exists and is not expired
	foundNonce, fnErr := ua.nonceService.GetNonce(inputRegister.Nonce)
	if fnErr != nil {
		ApiErrorf(c, http.StatusUnauthorized, "nonce not found")
		return
	}

	millisecondsNow := time.Now().UTC().UnixMilli() - int64(5*60*1000) // 5 mintes ago
	if foundNonce.Created < millisecondsNow {
		ApiErrorf(c, http.StatusUnauthorized, "nonce expired")
		return
	}

	validErr := apiutil.ValidateMailioKeys(inputRegister.Email, inputRegister.Ed25519SigningPublicKeyBase64, foundNonce.Nonce, inputRegister.MailioAddress)
	if validErr != nil {
		if validErr == types.ErrSignatureInvalid {
			ApiErrorf(c, http.StatusUnauthorized, "invalid signature")
			return
		} else if validErr == types.ErrInvalidPublicKey {
			ApiErrorf(c, http.StatusUnauthorized, "invalid public key")
			return
		} else if validErr == types.ErrNotFound {
			ApiErrorf(c, http.StatusUnauthorized, "nonce not found")
			return
		} else if validErr == types.ErrInvalidMailioAddress {
			ApiErrorf(c, http.StatusUnauthorized, "invalid mailio address")
			return
		}
		ApiErrorf(c, http.StatusInternalServerError, "failed to validate signature")
		return
	}
	// delete nonce from database (don't fail if nonce not found)
	ua.nonceService.DeleteNonce(foundNonce.Nonce)

	// if everything checks out, create users database, DID document and Verifiable Credential of owning the email address
	// then store all to database
	emailAddr, _ := mail.ParseAddress(inputRegister.Email)
	scryptedEmail, sErr := util.ScryptEmail(emailAddr.Address)
	if sErr != nil {
		ApiErrorf(c, http.StatusInternalServerError, "Failed to scrypt email")
		return
	}

	user := &types.User{
		Email:          emailAddr.Address,
		EncryptedEmail: base64.URLEncoding.EncodeToString(scryptedEmail),
		MailioAddress:  inputRegister.MailioAddress,
		Created:        util.GetTimestamp(),
	}
	mk, mkErr := apiutil.CreateDIDKey(inputRegister.Ed25519SigningPublicKeyBase64, inputRegister.X25519PublicKeyBase64)
	if mkErr != nil {
		if mkErr == types.ErrInvalidPublicKey {
			ApiErrorf(c, http.StatusUnauthorized, "invalid public key")
			return
		}
		ApiErrorf(c, http.StatusInternalServerError, "Failed to create DID key")
		return
	}
	// create user database
	_, errCU := ua.userService.CreateUser(user, mk, inputRegister.DatabasePassword)
	if errCU != nil {
		if errCU == types.ErrUserExists {
			ApiErrorf(c, http.StatusConflict, "user already exists")
			return
		}
		if errCU == types.ErrConflict {
			ApiErrorf(c, http.StatusConflict, "user already exists")
			return
		}
		if errCU == types.ErrDomainNotFound {
			ApiErrorf(c, http.StatusConflict, "domain not supported")
			return
		}
		ApiErrorf(c, http.StatusBadRequest, errCU.Error())
		return
	}

	token, tErr := setCookieAndGenerateToken(c, mk, inputRegister.Nonce, inputRegister.Ed25519SigningPublicKeyBase64)
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
// @Success 200 {object} types.OutputUserAddress
// @Failure 429 {object} api.ApiError "rate limit exceeded"
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
	output := &types.OutputUserAddress{
		Address: mapping.MailioAddress,
	}
	c.JSON(http.StatusOK, output)
}

// Get logged in users basic information
// @Security Bearer
// @Summary Get logged inusers basic information
// @Description Get logged in users basic information
// @Tags User Account
// @Success 200 {object} types.OutputBasicUserInfo
// @Failure 429 {object} api.ApiError "rate limit exceeded"
// @Accept json
// @Produce json
// @Router /api/v1/user/me [get]
func (ua *UserAccountApi) GetUserAddress(c *gin.Context) {
	address := c.GetString("subjectAddress")
	if address == "" {
		ApiErrorf(c, http.StatusUnauthorized, "address not found")
		return
	}
	totalDiskUsageFromHandlers := int64(0)
	for _, diskUsageHandler := range diskusage.Handlers() {
		awsDiskUsage, awsDuErr := diskusage.GetHandler(diskUsageHandler).GetDiskUsage(address)
		if awsDuErr != nil {
			if awsDuErr != diskusagehandlers.ErrNotFound {
				global.Logger.Log("error retrieving disk usage stats", awsDuErr.Error())
			}
		}
		if awsDiskUsage != nil {
			totalDiskUsageFromHandlers += awsDiskUsage.SizeBytes
		}
	}
	stats, sErr := ua.userProfileService.Stats(address)
	if sErr != nil {
		global.Logger.Log("error retrieving disk usage stats", sErr.Error())
	}
	up, err := ua.userProfileService.Get(address)
	if err != nil {
		ApiErrorf(c, http.StatusInternalServerError, "user profile not found")
		return
	}
	output := &types.OutputBasicUserInfo{
		Address:   address,
		TotalDisk: up.DiskSpace,
		UsedDisk:  totalDiskUsageFromHandlers + stats.ActiveSize,
		Created:   up.Created,
	}
	c.JSON(http.StatusOK, output)
}

// Get logged in users smartkey based on a JWS token
// @Security Bearer
// @Summary Get logged in users smartkey based on a JWS token
// @Description Get logged in users smartkey based on a JWS token
// @Tags User Account
// @Success 200 {object} types.OutputBasicUserInfo
// @Failure 429 {object} api.ApiError "rate limit exceeded"
// @Accept json
// @Produce json
// @Router /api/v1/user/me [get]
func (ua *UserAccountApi) VerifyCookie(c *gin.Context) {
	// check if user is logged in
	address := c.GetString("subjectAddress")
	if address == "" {
		ApiErrorf(c, http.StatusUnauthorized, "address not found")
		return
	}
	// get the encrypted smartkey
	smartKey, skErr := ua.smartKeyService.GetSmartKey(address)
	if skErr != nil {
		ApiErrorf(c, http.StatusForbidden, "smartkey not found")
		return
	}
	// create response
	output := types.JwsTokenWithSmartKey{
		EncryptedSmartKeyBase64: smartKey.SmartKeyEncrypted,
		JwsToken:                "",
		SmartKeyPasswordPart:    smartKey.PasswordShare,
		Email:                   smartKey.Email,
	}

	c.JSON(http.StatusOK, output)
}
