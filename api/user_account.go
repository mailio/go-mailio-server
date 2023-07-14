package api

import (
	"crypto"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/mail"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-jose/go-jose/v3"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	mailiocrypto "github.com/mailio/go-mailio-core/crypto"
	"github.com/mailio/go-mailio-core/did"
	"github.com/mailio/go-mailio-server/global"
	"github.com/mailio/go-mailio-server/services"
	"github.com/mailio/go-mailio-server/types"
	"github.com/mailio/go-mailio-server/util"
)

type UserAccountApi struct {
	userService  *services.UserService
	nonceService *services.NonceService
	validate     *validator.Validate
}

func NewUserAccountApi(userService *services.UserService, nonceService *services.NonceService) *UserAccountApi {
	return &UserAccountApi{
		userService:  userService,
		nonceService: nonceService,
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
	if !util.IsEd25519PublicKey(inputRegister.Ed25519SigningPublicKeyBase64) {
		ApiErrorf(c, http.StatusBadRequest, "invalid signing public key")
		return
	}
	if !util.IsEd25519PublicKey(inputRegister.X25519PublicKeyBase64) {
		ApiErrorf(c, http.StatusBadRequest, "invalid encryption public key")
		return
	}
	signingKeyBytes, _ := base64.StdEncoding.DecodeString(inputRegister.Ed25519SigningPublicKeyBase64)
	signingKey := crypto.PublicKey(signingKeyBytes)
	encryptionKeyBytes, _ := base64.StdEncoding.DecodeString(inputRegister.X25519PublicKeyBase64)
	encryptionPublicKey := crypto.PublicKey(encryptionKeyBytes)

	signatureBytes, sErr := base64.StdEncoding.DecodeString(inputRegister.SignatureBase64)
	if sErr != nil {
		ApiErrorf(c, http.StatusBadRequest, "invalid signature")
		return
	}

	// verify signature
	isValid := ed25519.Verify(signingKeyBytes, []byte(inputRegister.Nonce), signatureBytes)
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
	// map sacrypt (encrryped email) address to mailio address
	_, errMu := ua.userService.MapEmailToMailioAddress(user)
	if errMu != nil {
		ApiErrorf(c, http.StatusInternalServerError, "failed to create user to address mapping")
		return
	}
	// create user database
	_, errCU := ua.userService.CreateUser(user, inputRegister.DatabasePassword)
	if errCU != nil {
		ApiErrorf(c, http.StatusBadRequest, err.Error())
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
	userDIDDoc, didErr := did.NewMailioDIDDocument(mk, global.PublicKey)
	if didErr != nil {
		ApiErrorf(c, http.StatusInternalServerError, "Failed to create DID document")
		return
	}
	// TODO! finish up here (store in database)
	fmt.Printf("%v\n", userDIDDoc)

	// proof that user owns the email address at this domain
	newCredId := uuid.New().String()
	newVC := did.NewVerifiableCredential(global.MailioDID.String())
	newVC.IssuanceDate = time.Now().UTC()
	newVC.ID = global.Conf.Mailio.Domain + "/api/v1/credentials/" + newCredId
	credentialSubject := did.CredentialSubject{
		ID: mk.DID(),
		AuthorizedApplication: &did.AuthorizedApplication{
			ID:           mk.DID(),
			Domains:      []string{global.Conf.Mailio.Domain},
			ApprovalDate: time.Now(),
		},
	}
	newVC.CredentialSubject = credentialSubject
	newVC.CredentialStatus = &did.CredentialStatus{
		ID:   global.Conf.Mailio.Domain + "/api/v1/credentials/" + newCredId + "/status",
		Type: "CredentialStatusList2017",
	}
	vcpErr := newVC.CreateProof(global.PrivateKey)
	if vcpErr != nil {
		ApiErrorf(c, http.StatusInternalServerError, "Failed to create proof")
		return
	}
	// TODO! store in database the newly generate VC
	fmt.Printf("%v\n", newVC)

	token, tErr := generateJWSToken(global.PrivateKey, mk.DID(), inputRegister.Nonce)
	if tErr != nil {
		ApiErrorf(c, http.StatusInternalServerError, "Failed to sign token")
		return
	}

	c.JSON(http.StatusOK, gin.H{"token": token})
}
