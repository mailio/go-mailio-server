package util

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	src "math/rand"
	"regexp"

	"github.com/mailio/go-mailio-server/types"
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

func ScryptEmail(email string) (string, error) {
	dk, err := scrypt.Key([]byte(email), []byte(email), scryptN, scryptR, scryptP, scryptLen)
	if err != nil {
		return "", err
	}
	// Encode the hashed result to base64
	return base64.StdEncoding.EncodeToString(dk), nil
}

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
const (
	letterIdxBits = 6                    // 6 bits to represent a letter index
	letterIdxMask = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
	letterIdxMax  = 63 / letterIdxBits   // # of letter indices fitting in 63 bits
)

// Generates a random nonce of custom length in bytes
// method based on https://stackoverflow.com/questions/22892120/how-to-generate-a-random-string-of-a-fixed-length-in-go
// 5. Masking improved version
func GenerateNonce(n int) string {
	b := make([]byte, n)
	// A src.Int63() generates 63 random bits, enough for letterIdxMax characters!
	for i, cache, remain := n-1, src.Int63(), letterIdxMax; i >= 0; {
		if remain == 0 {
			cache, remain = src.Int63(), letterIdxMax
		}
		if idx := int(cache & letterIdxMask); idx < len(letterBytes) {
			b[i] = letterBytes[idx]
			i--
		}
		cache >>= letterIdxBits
		remain--
	}

	return string(b)
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

func PublicKeyToMailioAddress(pubKeyRaw []byte) (string, error) {
	// decoded, err := base64.StdEncoding.DecodeString(pubKeyBase64)
	// if err != nil {
	// 	return "", err
	// }
	// hash := sha256.New()
	// _, werr := hash.Write(decoded)
	// if werr != nil {
	// 	return "", err
	// }
	// sh256Bytes := hash.Sum(nil)
	// ma := BytesToAddress(sh256Bytes)
	// return hex.EncodeToString(ma[:]), nil
	// pubKey, err := base64.RawURLEncoding.DecodeString(pubKeyBase64)
	// if err != nil {
	// return "", err
	// }
	return RawPublicKeyToMailioAddress(pubKeyRaw)
}

func RawPublicKeyToMailioAddress(pubKey ed25519.PublicKey) (string, error) {
	if len(pubKey) != 32 {
		return "", types.ErrInvalidPublicKey
	}

	h := sha256.New()
	h.Write([]byte(base64.StdEncoding.EncodeToString(pubKey)))
	output := hex.EncodeToString(h.Sum(nil))
	output = "0x" + output[64-40:64]
	return output, nil
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

// Sha256Hex returns the sha256 hash of the data as a hex string
func Sha256Hex(data []byte) string {
	hash := sha256.New()
	hash.Write(data)
	sum := hash.Sum(nil)
	return hex.EncodeToString(sum)
}

// Signing message using ed25519
func Sign(message []byte, privateKey ed25519.PrivateKey) ([]byte, error) {
	if len(privateKey) != 64 {
		return nil, types.ErrInvalidPrivateKey
	}
	signature := ed25519.Sign(privateKey, message)
	return signature, nil
}

// Verify message signature using ed25519
func Verify(message []byte, signature []byte, publicKeyBase64 string) (bool, error) {
	pubKey, err := base64.StdEncoding.DecodeString(publicKeyBase64)
	if err != nil {
		return false, err
	}
	if len(pubKey) != 32 {
		return false, types.ErrInvalidPublicKey
	}

	if ed25519.Verify(pubKey, message, signature) {
		return true, nil
	}
	return false, nil
}

// Generated ed25519 signing key pair and returns base64 public key, private key
// returns publicKey, privateKey, error
func GenerateEd25519KeyPair() (*string, *string, error) {
	pubKey, privKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, nil, err
	}

	pubKeyBase64 := base64.StdEncoding.EncodeToString(pubKey)
	privKeyBase64 := base64.StdEncoding.EncodeToString(privKey)
	return &pubKeyBase64, &privKeyBase64, nil
}

// helper to check if the mailio address is valid
func IsValidMailioAddress(address string) bool {
	re := regexp.MustCompile("^0x[0-9a-fA-F]{40}$")
	return re.MatchString(address)
}
