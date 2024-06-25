package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/mail"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/mailio/go-mailio-server/api/interceptors"
	"github.com/mailio/go-mailio-server/global"
	"github.com/mailio/go-mailio-server/services"
	"github.com/mailio/go-mailio-server/types"
	"github.com/mailio/go-mailio-server/util"
)

type WebAuthnApi struct {
	nonceService       *services.NonceService
	webauthnService    *services.WebAuthnService
	userService        *services.UserService
	validator          *validator.Validate
	env                *types.Environment
	rotationKeyService *services.RotationKeyService
}

func NewWebAuthnApi(nonceService *services.NonceService, webAuthnService *services.WebAuthnService, userService *services.UserService, rotationKeyService *services.RotationKeyService, env *types.Environment) *WebAuthnApi {
	return &WebAuthnApi{
		nonceService:       nonceService,
		validator:          validator.New(),
		env:                env,
		webauthnService:    webAuthnService,
		rotationKeyService: rotationKeyService,
		userService:        userService,
	}
}

// WebAuthnRegister godoc
// @Summary Registration options for a new WebAuthn device
// @Description Registration options for a new WebAuthn device
// @Tags WebAuthn
// @Accept json
// @Produce json
// @Param email query string true "Email address to register"
// @Success 200 {object} types.WebauthnRegistrationOptionsJSON
// @Failure 400 {object} api.ApiError "invalid email address"
// @Failure 429 {object} api.ApiError "rate limit exceeded"
// @Router /api/v1/webauthn/registration_options [get]
func (a *WebAuthnApi) RegistrationOptions(c *gin.Context) {
	email := c.Query("email")
	if email == "" {
		ApiErrorf(c, http.StatusBadRequest, "email query parameter is required")
		return
	}
	address := c.Query("address")
	if address == "" {
		ApiErrorf(c, http.StatusBadRequest, "address query parameter is required")
		return
	}
	// validate email:
	pe, err := mail.ParseAddress(email)
	if err != nil {
		ApiErrorf(c, 400, "invalid email address: %s", err)
		return
	}

	scryptedEmail, sErr := util.ScryptEmail(pe.Address)
	if sErr != nil {
		ApiErrorf(c, http.StatusInternalServerError, "Failed to scrypt email")
		return
	}
	// check if email already exists
	_, fuErr := a.userService.FindUserByScryptEmail(base64.URLEncoding.EncodeToString(scryptedEmail))
	if fuErr == nil {
		ApiErrorf(c, http.StatusConflict, "email already exists")
		return
	} else if fuErr != types.ErrNotFound {
		ApiErrorf(c, http.StatusInternalServerError, "failed to search for email")
		return
	}

	userDisplayName := pe.Name
	if userDisplayName == "" {
		userDisplayName = strings.Split(pe.Address, "@")[0]
	}

	user := &types.WebAuhnUser{
		ID:          []byte(address),
		Name:        pe.Address,
		DisplayName: userDisplayName,
	}
	options, session, err := a.env.WebAuthN.BeginRegistration(user)
	if err != nil {
		ApiErrorf(c, http.StatusInternalServerError, "failed to begin registration: %s", err)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	redisSesskey := "webauthn_user_sess_" + strings.Replace(address, "0x", "", -1)
	sessionBytes, sErr := json.Marshal(session)
	if sErr != nil {
		ApiErrorf(c, http.StatusInternalServerError, "failed to marshal session: %s", sErr)
		return
	}
	redStatus := a.env.RedisClient.Set(ctx, redisSesskey, sessionBytes, time.Minute*5)
	if redStatus.Err() != nil {
		global.Logger.Log("error", fmt.Sprintf("failed to save session: %s", redStatus.Err()))
		ApiErrorf(c, http.StatusInternalServerError, "failed to store session")
		return
	}
	// // store webauthn user too (why?)
	// uErr := a.webauthnService.SaveUser(user)
	// if uErr != nil {
	// 	global.Logger.Log("error", fmt.Sprintf("failed to save user: %s", uErr))
	// 	ApiErrorf(c, http.StatusInternalServerError, "failed to save user")
	// 	return
	// }

	c.JSON(http.StatusOK, options.Response)
}

// WebAuthnVerifyRegistration godoc
// @Summary WebAuthnVerifyRegistration check the validity of the registration
// @Description WebAuthnVerifyRegistration check the signed digital challenge
// @Tags WebAuthn
// @Accept json
// @Produce json
// @Param body body types.WebauthRegistrationVerify true "Attestation object + Encrypted SmartKey payload"
// @Success 200 {object} types.WebAuthnRegistrationVerifyResponse
// @Failure 400 {object} api.ApiError "invalid input parameters"
// @Failure 429 {object} api.ApiError "rate limit exceeded"
// @Router /api/v1/webauthn/registration_verify [post]
func (a *WebAuthnApi) VerifyRegistration(c *gin.Context) {
	var req types.WebauthRegistrationVerify
	if err := c.ShouldBindJSON(&req); err != nil {
		ApiErrorf(c, http.StatusBadRequest, "invalid request: %s", err)
		return
	}

	err := a.validator.Struct(req)
	if err != nil {
		msg := util.ValidationErrorToMessage(err)
		ApiErrorf(c, http.StatusBadRequest, msg)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	redisSesskey := "webauthn_user_sess_" + strings.Replace(req.SmartKeyPayload.Address, "0x", "", -1)
	sessBytes, err := a.env.RedisClient.Get(ctx, redisSesskey).Result()
	if err != nil {
		global.Logger.Log("error", fmt.Sprintf("failed to get session: %s", err))
		ApiErrorf(c, http.StatusForbidden, "session not found")
		return
	}
	var session webauthn.SessionData
	err = json.Unmarshal([]byte(sessBytes), &session)
	if err != nil {
		global.Logger.Log("error", fmt.Sprintf("failed to unmarshal session: %s", err))
		ApiErrorf(c, http.StatusInternalServerError, "failed to unmarshal session")
		return
	}

	// validate email address
	pe, err := mail.ParseAddress(req.SmartKeyPayload.Email)
	if err != nil {
		ApiErrorf(c, http.StatusBadRequest, "invalid email address: %s", err)
		return
	}
	if pe.Name == "" {
		pe.Name = strings.Split(pe.Address, "@")[0]
	}

	scryptedEmail, sErr := util.ScryptEmail(req.SmartKeyPayload.Email)
	if sErr != nil {
		ApiErrorf(c, http.StatusInternalServerError, "Failed to scrypt email")
		return
	}
	// check if email already exists
	_, fuErr := a.userService.FindUserByScryptEmail(base64.URLEncoding.EncodeToString(scryptedEmail))
	if fuErr == nil {
		ApiErrorf(c, http.StatusConflict, "email already exists")
		return
	} else if fuErr != types.ErrNotFound {
		ApiErrorf(c, http.StatusInternalServerError, "failed to search for email")
		return
	}

	user := &types.WebAuhnUser{
		ID:          []byte(req.SmartKeyPayload.Address),
		Name:        pe.Address,
		DisplayName: pe.Name,
	}

	// due to the design of the webauthn library, we need to parse the response
	// basically implement our own FinishRegistration method here
	attRespMrsh, mrshErr := json.Marshal(req.AttestationResponse)
	if mrshErr != nil {
		ApiErrorf(c, http.StatusInternalServerError, "failed to marshal attestation response: %s", mrshErr)
		return
	}
	reader := io.NopCloser(bytes.NewReader(attRespMrsh))
	pcc, pccErr := protocol.ParseCredentialCreationResponseBody(reader)
	if pccErr != nil {
		global.Logger.Log("error", fmt.Sprintf("failed to parse credential creation response: %s", pccErr))
		ApiErrorf(c, http.StatusForbidden, "failed to finish registration")
		return
	}
	credential, cErr := a.env.WebAuthN.CreateCredential(user, session, pcc)
	if cErr != nil {
		global.Logger.Log("error", fmt.Sprintf("failed to create credential: %s", cErr))
		ApiErrorf(c, http.StatusInternalServerError, "Failed to finish registration. Please contact support.")
		return
	}
	// store the credential within the user object
	if user.Credentials == nil {
		user.Credentials = make([]webauthn.Credential, 0)
	}
	// check if credential already exists, add if it doesn't
	credentialExists := false
	for _, cred := range user.Credentials {
		if bytes.Equal(cred.ID, credential.ID) {
			credentialExists = true
		}
	}
	if !credentialExists {
		user.Credentials = append(user.Credentials, *credential)
	}

	suErr := a.webauthnService.SaveUser(user)
	if suErr != nil {
		global.Logger.Log("error", fmt.Sprintf("failed to save user: %s", suErr))
		ApiErrorf(c, http.StatusInternalServerError, "failed to save user")
		return
	}
	// remove the session from redis
	_, delErr := a.env.RedisClient.Del(ctx, redisSesskey).Result()
	if delErr != nil {
		global.Logger.Log("error", fmt.Sprintf("failed to delete session: %s", delErr))
	}

	// create the uses database, indexes, mapping, Verifiable Credentials (proof that is Mailio user) and public DID
	nonWebauthnUser := &types.User{
		MailioAddress:  req.SmartKeyPayload.Address,
		Email:          req.SmartKeyPayload.Email,
		EncryptedEmail: base64.URLEncoding.EncodeToString(scryptedEmail),
		Created:        time.Now().UTC().UnixMilli(),
	}
	// create JWT key
	// create DID ID and DID document and store it in database!
	mk, mkErr := CreateDIDKey(req.SmartKeyPayload.PrimaryEd25519PublicKey, req.SmartKeyPayload.PrimaryX25519PublicKey)
	if mkErr != nil {
		ApiErrorf(c, http.StatusForbidden, "Failed to create DID key")
		return
	}

	_, cuErr := a.userService.CreateUser(nonWebauthnUser, mk, req.SmartKeyPayload.DatabasePassword)
	if cuErr != nil {
		if cuErr == types.ErrUserExists {
			ApiErrorf(c, http.StatusConflict, "user already exists")
			return
		}
		if cuErr == types.ErrConflict {
			ApiErrorf(c, http.StatusConflict, "user already exists")
			return
		}
		if cuErr == types.ErrDomainNotFound {
			ApiErrorf(c, http.StatusConflict, "domain not supported")
			return
		}
		ApiErrorf(c, http.StatusBadRequest, "failed to register user")
		return
	}

	// save SmartKeyPayload to the database
	rotKey := &types.RotationKey{
		Address:                 req.SmartKeyPayload.Address,
		PrimaryEd25519PublicKey: req.SmartKeyPayload.PrimaryEd25519PublicKey,
		PrimaryX25519PublicKey:  req.SmartKeyPayload.PrimaryX25519PublicKey,
		Email:                   req.SmartKeyPayload.Email,
		ChallengeSignature:      req.SmartKeyPayload.ChallengeSignature,
		PreRotatedMailioKey:     req.SmartKeyPayload.PreRotatedMailioKey,
		PasswordShare:           req.SmartKeyPayload.PasswordShare,
		Created:                 time.Now().UTC().UnixMilli(),
	}
	rkErr := a.rotationKeyService.SaveRotationKey(rotKey)
	if rkErr != nil {
		ApiErrorf(c, http.StatusExpectationFailed, "Failed to save rotation key")
		return
	}

	token, tErr := interceptors.GenerateJWSToken(global.PrivateKey, mk.DID(), global.MailioDID, session.Challenge, req.SmartKeyPayload.PrimaryEd25519PublicKey)
	if tErr != nil {
		ApiErrorf(c, http.StatusInternalServerError, "Failed to sign token")
		return
	}

	c.JSON(http.StatusOK, gin.H{"token": token})
}
