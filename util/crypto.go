package util

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"

	"github.com/mailio/go-mailio-server/global"
	"golang.org/x/crypto/scrypt"
)

const (
	AddressLength = 20 // bytes
)

// MailioAddress represents the 20 byte address (same as Ethereum account).
type MailioAddress [AddressLength]byte

var (
	scryptN   = 32768 // N = CPU/memory cost parameter (suitable as of 2017)
	scryptR   = 8     // r and p must satisfy r * p < 2^30
	scryptP   = 1
	scryptLen = 32 // 32 bytes long
)

func ScryptEmail(email string) ([]byte, error) {
	slt := global.Conf.Mailio.EmailSaltHex
	if slt == "" {
		return nil, errors.New("emailSalt configuration is empty")
	}
	emailSalt, dErr := hex.DecodeString(slt)
	if dErr != nil {
		return nil, dErr
	}

	dk, err := scrypt.Key([]byte(email), emailSalt, scryptN, scryptR, scryptP, scryptLen)
	if err != nil {
		return nil, err
	}
	return dk, nil
}

// Generates a random nonce of custom length in bytes
func GenerateNonce(lengthInBytes int) (string, error) {
	nonce := make([]byte, lengthInBytes)

	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}

	return base64.URLEncoding.EncodeToString(nonce), nil
}

// Check if a base64 string is an ed25519 public key.
func IsEd25519PublicKey(b64Key string) bool {
	decoded, err := base64.StdEncoding.DecodeString(b64Key)
	if err != nil {
		// Base64 decoding error.
		return false
	}
	if len(decoded) != ed25519.PublicKeySize {
		// The key is not the correct size.
		return false
	}

	// It's a valid size, so we'll assume it's an Ed25519 public key.
	return true
}

func PublicKeyToMailioAddress(pubKeyBase64 string) (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(pubKeyBase64)
	if err != nil {
		return "", err
	}
	hash := sha256.New()
	_, werr := hash.Write(decoded)
	if werr != nil {
		return "", err
	}
	sh256Bytes := hash.Sum(nil)
	ma := BytesToAddress(sh256Bytes)
	return hex.EncodeToString(ma[:]), nil
}

// SetBytes sets the address to the value of b.
// If b is larger than len(a), b will be cropped from the left.
func (a *MailioAddress) SetBytes(b []byte) {
	if len(b) > len(a) {
		b = b[len(b)-AddressLength:]
	}
	copy(a[AddressLength-len(b):], b)
}

// BytesToAddress returns Address with value b.
// If b is larger than len(h), b will be cropped from the left.
func BytesToAddress(b []byte) MailioAddress {
	var a MailioAddress
	a.SetBytes(b)
	return a
}
