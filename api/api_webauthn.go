package api

import (
	"bytes"
	"context"
	"crypto/ed25519"
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
	"github.com/mailio/go-mailio-did/did"
	"github.com/mailio/go-mailio-server/api/interceptors"
	apiutil "github.com/mailio/go-mailio-server/api/util"
	"github.com/mailio/go-mailio-server/global"
	"github.com/mailio/go-mailio-server/services"
	"github.com/mailio/go-mailio-server/types"
	"github.com/mailio/go-mailio-server/util"
	"github.com/redis/go-redis/v9"
)

type WebAuthnApi struct {
	nonceService         *services.NonceService
	webauthnService      *services.WebAuthnService
	userService          *services.UserService
	userProfileService   *services.UserProfileService
	validator            *validator.Validate
	env                  *types.Environment
	smartKetService      *services.SmartKeyService
	serfSovereignService *services.SelfSovereignService
}

func NewWebAuthnApi(nonceService *services.NonceService, webAuthnService *services.WebAuthnService, userService *services.UserService, userProfileService *services.UserProfileService, smartKeyService *services.SmartKeyService, ssi *services.SelfSovereignService, env *types.Environment) *WebAuthnApi {
	return &WebAuthnApi{
		nonceService:         nonceService,
		validator:            validator.New(),
		env:                  env,
		webauthnService:      webAuthnService,
		smartKetService:      smartKeyService,
		userService:          userService,
		serfSovereignService: ssi,
		userProfileService:   userProfileService,
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

	// verify challenge signature with primary key
	// as a proof user has access to the primary key
	sign, b64Err := base64.StdEncoding.DecodeString(req.SmartKeyPayload.ChallengeSignature)
	if b64Err != nil {
		ApiErrorf(c, http.StatusBadRequest, "failed to decode challenge signature: %s", b64Err)
		return
	}
	isValid, vErr := util.Verify([]byte(session.Challenge), sign, req.SmartKeyPayload.PrimaryEd25519PublicKey)
	if vErr != nil {
		ApiErrorf(c, http.StatusBadRequest, "failed to verify Mailio challenge signature: %s", vErr)
		return
	}
	if !isValid {
		ApiErrorf(c, http.StatusForbidden, "invalid challenge signature")
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
	mk, mkErr := apiutil.CreateDIDKey(req.SmartKeyPayload.PrimaryEd25519PublicKey, req.SmartKeyPayload.PrimaryX25519PublicKey)
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
	smrtKey := &types.SmartKey{
		Address:                 req.SmartKeyPayload.Address,
		PrimaryEd25519PublicKey: req.SmartKeyPayload.PrimaryEd25519PublicKey,
		PrimaryX25519PublicKey:  req.SmartKeyPayload.PrimaryX25519PublicKey,
		Email:                   req.SmartKeyPayload.Email,
		PreRotatedMailioKey:     req.SmartKeyPayload.PreRotatedMailioKey,
		SmartKeyEncrypted:       req.SmartKeyPayload.SmartKeyEncrypted,
		PasswordShare:           req.SmartKeyPayload.PasswordShare,
		Created:                 time.Now().UTC().UnixMilli(),
	}
	rkErr := a.smartKetService.SaveSmartKey(smrtKey)
	if rkErr != nil {
		ApiErrorf(c, http.StatusExpectationFailed, "Failed to save rotation key")
		return
	}

	token, tErr := a.setCookieAndGenerateToken(c, mk, session.Challenge, req.SmartKeyPayload.PrimaryEd25519PublicKey)
	if tErr != nil {
		ApiErrorf(c, http.StatusInternalServerError, "failed to generate jws token")
		return
	}

	c.JSON(http.StatusOK, gin.H{"token": token})
}

// LoginOptions godoc
// @Summary LoginOptions return login options
// @Description LoginOptions return WebAuthN login options
// @Tags WebAuthn
// @Accept json
// @Produce json
// @Success 200 {object} protocol.PublicKeyCredentialRequestOptions
// @Failure 400 {object} api.ApiError "invalid input parameters"
// @Failure 429 {object} api.ApiError "rate limit exceeded"
// @Router /api/v1/webauthn/login_options [get]
func (a *WebAuthnApi) LoginOptions(c *gin.Context) {
	options, session, err := a.env.WebAuthN.BeginDiscoverableLogin()
	if err != nil {
		ApiErrorf(c, http.StatusInternalServerError, "failed to begin login: %s", err)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	redisSesskey := "webauthn_user_sess_" + session.Challenge
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

	c.JSON(http.StatusOK, options.Response)
}

// LoginVerify godoc
// @Summary LoginOptions return login options
// @Description LoginOptions return WebAuthN login options
// @Tags WebAuthn
// @Accept json
// @Produce json
// @Param body protocol.ParsedCredentialAssertionData true "Credential Assertion Data"
// @Success 200 {object} protocol.PublicKeyCredentialRequestOptions
// @Failure 400 {object} api.ApiError "invalid input parameters"
// @Failure 429 {object} api.ApiError "rate limit exceeded"
// @Router /api/v1/webauthn/login_verify [post]
func (a *WebAuthnApi) LoginVerify(c *gin.Context) {

	var req protocol.CredentialAssertionResponse
	if err := c.ShouldBindJSON(&req); err != nil {
		ApiErrorf(c, http.StatusBadRequest, "invalid request: %s", err)
		return
	}

	clientData, cdErr := util.FixAndDecodeURLBase64(req.AssertionResponse.ClientDataJSON.String())
	if cdErr != nil {
		ApiErrorf(c, http.StatusBadRequest, "failed to decode clientDataJSON: %s", cdErr)
		return
	}
	var clientDataJson map[string]interface{}
	cdErr = json.Unmarshal(clientData, &clientDataJson)
	if cdErr != nil {
		ApiErrorf(c, http.StatusBadRequest, "failed to unmarshal clientDataJSON: %s", cdErr)
		return
	}
	challenge := clientDataJson["challenge"].(string)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	redisSesskey := "webauthn_user_sess_" + challenge
	redStatus, rErr := a.env.RedisClient.Get(ctx, redisSesskey).Result()
	if rErr == redis.Nil {
		ApiErrorf(c, http.StatusForbidden, "session not found")
		return
	} else if rErr != nil {
		global.Logger.Log("error", fmt.Sprintf("failed to save session: %s", rErr.Error()))
		ApiErrorf(c, http.StatusInternalServerError, "failed to retrieve session")
		return
	}
	var session webauthn.SessionData
	uErr := json.Unmarshal([]byte(redStatus), &session)
	if uErr != nil {
		global.Logger.Log("error", fmt.Sprintf("failed to unmarshal session: %s", uErr))
		ApiErrorf(c, http.StatusInternalServerError, "failed to unmarshal session")
		return
	}

	reqMars, rmErr := json.Marshal(req)
	if rmErr != nil {
		ApiErrorf(c, http.StatusInternalServerError, "failed to marshal request: %s", rmErr)
		return
	}

	reader := io.NopCloser(bytes.NewReader(reqMars))
	parsedResponse, err := protocol.ParseCredentialRequestResponseBody(reader)
	if err != nil {
		ApiErrorf(c, http.StatusBadRequest, "failed to parse credential request response: %s", err)
		return
	}

	credential, err := a.env.WebAuthN.ValidateDiscoverableLogin(a.WebauthnUserHandler, session, parsedResponse)
	if err != nil {
		ApiErrorf(c, http.StatusForbidden, "failed to validate login: %s", err)
		return
	}
	fmt.Printf("Credential: %+v\n", credential)
	userMailioAddress := string(parsedResponse.Response.UserHandle)

	// check if user enabled
	userProfile, upErr := a.userProfileService.Get(userMailioAddress)
	if upErr != nil {
		if upErr == types.ErrNotFound {
			ApiErrorf(c, http.StatusForbidden, "no user profile found")
			return
		}
		ApiErrorf(c, http.StatusInternalServerError, "failed to retrieve user profile")
		return
	}
	if !userProfile.Enabled {
		ApiErrorf(c, http.StatusForbidden, "user account disabled")
		return
	}

	userDIDDoc, udErr := a.serfSovereignService.GetDIDDocument(userMailioAddress)
	if udErr != nil {
		ApiErrorf(c, http.StatusForbidden, "user not found")
		return
	}
	if len(userDIDDoc.VerificationMethod) <= 0 {
		ApiErrorf(c, http.StatusForbidden, "invalid did document")
		return
	}
	pk, pkErr := userDIDDoc.VerificationMethod[0].PublicKeyJwk.GetRawKey()
	if pkErr != nil {
		ApiErrorf(c, http.StatusInternalServerError, "public key not stored")
		return
	}
	cpk, ok := pk.(ed25519.PublicKey)
	if !ok {
		ApiErrorf(c, http.StatusInternalServerError, "unssuported public key")
		return
	}
	mk := &did.MailioKey{
		MasterSignKey: &did.Key{
			PublicKey: cpk,
		},
	}

	encodedPublicKey := base64.StdEncoding.EncodeToString(cpk)

	jwsToken, jwsErr := a.setCookieAndGenerateToken(c, mk, challenge, encodedPublicKey)
	if jwsErr != nil {
		ApiErrorf(c, http.StatusInternalServerError, "failed to generate jws token")
		return
	}
	c.JSON(http.StatusOK, gin.H{"token": jwsToken})
}

func (a *WebAuthnApi) WebauthnUserHandler(rawID, userHandle []byte) (webauthn.User, error) {
	// implmeneting user handler to fit the webauthn library requirements
	webauthUser, waErr := a.webauthnService.GetUser(string(userHandle))
	if waErr != nil {
		return nil, waErr
	}

	return webauthUser, nil
}

// set cookie in the response (httpOnly)
func (a *WebAuthnApi) setCookieAndGenerateToken(c *gin.Context, userDID *did.MailioKey, challenge string, usersPrimaryEd25519PublicKey string) (string, error) {
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
	httpOnly := true
	if strings.Contains(*domain, "localhost") || strings.Contains(*domain, "::1") || strings.Contains(*domain, "127.0.0.1") {
		secure = false
		d := "localhost"
		domain = &d
	}

	c.SetCookie("token", token, 60*60*24, "/", *domain, secure, httpOnly) // 1 day // httpOnly: true

	return token, nil
}
