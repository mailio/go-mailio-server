package apiutil

import (
	"net"
	"strings"

	"crypto/ed25519"
	"encoding/base64"
	"net/mail"

	"github.com/gin-gonic/gin"

	"github.com/mailio/go-mailio-did/did"
	"github.com/mailio/go-mailio-server/global"
	"github.com/mailio/go-mailio-server/types"
	"github.com/mailio/go-mailio-server/util"
)

func GetIPFromContext(c *gin.Context) (*string, error) {
	ip := c.Request.Header.Get("X-Real-IP")
	if len(ip) > 0 {
		return &ip, nil
	}

	ip = c.Request.Header.Get("CloudFront-Forwarded-Proto")
	if len(ip) > 0 {
		return &ip, nil
	}

	ip = c.Request.Header.Get("X-Forwarded-For")
	ipList := strings.Split(ip, ",")
	if len(ipList[0]) > 0 {
		return &ipList[0], nil
	}

	// If there is no "X-Real-IP", "CloudFront-Forwarded-Proto" or "X-Forwarded-For", get IP from "RemoteAddr"
	ip, _, err := net.SplitHostPort(c.Request.RemoteAddr)
	if err != nil {
		return nil, err
	}
	return &ip, nil
}

// Validate signature from the input data
func validateSignature(inputChallenge string, ed25519PublicKeyBase64 string, signatureBase64 string) (bool, error) {

	if !util.IsEd25519PublicKey(ed25519PublicKeyBase64) {
		return false, types.ErrInvalidPublicKey
	}
	signingKeyBytes, _ := base64.StdEncoding.DecodeString(ed25519PublicKeyBase64)

	signatureBytes, sErr := base64.StdEncoding.DecodeString(signatureBase64)
	if sErr != nil {
		return false, types.ErrSignatureInvalid
	}

	// verify signature
	isValid := ed25519.Verify(signingKeyBytes, []byte(inputChallenge), signatureBytes)

	return isValid, nil
}

// Validate the mailio keys
// email: email address
// ed25519PublicKey: ed25519 public key
// challengeNonce: challenge nonce
// mailioAddress: mailio address
// returns error if validation fails (ErrInvalidPublicKey, ErrSignatureInvalid, ErrInvalidMailioAddress)
func ValidateMailioKeys(email string, ed25519PublicKey string, challengeNonce string, mailioAddress string) error {
	_, err := mail.ParseAddress(email)
	if err != nil {
		global.Logger.Log("error", "invalid email address", "email", email, "error", err)
		return err
	}
	if !util.IsEd25519PublicKey(ed25519PublicKey) {
		return types.ErrInvalidPublicKey
	}

	// validate siganture
	isValid, validErr := validateSignature(challengeNonce, ed25519PublicKey, challengeNonce)
	if validErr != nil {
		return validErr
	}
	if !isValid {
		return types.ErrSignatureInvalid
	}
	pubKeyFRomBase, dErr := base64.StdEncoding.DecodeString(ed25519PublicKey)
	if dErr != nil {
		return types.ErrInvalidPublicKey
	}
	ma, err := util.PublicKeyToMailioAddress(pubKeyFRomBase)
	if err != nil {
		return types.ErrInvalidMailioAddress
	}
	// validate mailio address format
	if mailioAddress != ma {
		return types.ErrInvalidMailioAddress
	}
	return nil
}

// CreateDIDKey creates a new DID key
func CreateDIDKey(ed25519PublicKeyBase64 string, x25519PublicKeyBase64 string) (*did.MailioKey, error) {
	// create DID ID and DID document and store it in database!
	signingKeyBytes, skBytesErr := base64.StdEncoding.DecodeString(ed25519PublicKeyBase64)
	if skBytesErr != nil {
		return nil, types.ErrInvalidPublicKey
	}
	signingKey := ed25519.PublicKey(signingKeyBytes)
	encryptionKeyBytes, ekBytesErr := base64.StdEncoding.DecodeString(x25519PublicKeyBase64)
	if ekBytesErr != nil {
		return nil, types.ErrInvalidPublicKey
	}
	encryptionPublicKey := ed25519.PublicKey(encryptionKeyBytes)
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
	return mk, nil
}
