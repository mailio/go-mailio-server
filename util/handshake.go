package util

import (
	"crypto/ed25519"
	"encoding/base64"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/mailio/go-mailio-server/types"
)

// Converting StoredHandshake to Handshake (user doesn't need details of revisions for now)
func StoredHandshakeToModelHandsake(storedHandshake *types.StoredHandshake) *types.Handshake {
	output := &types.Handshake{
		Content:           storedHandshake.Content,
		SignatureBase64:   storedHandshake.SignatureBase64,
		CborPayloadBase64: storedHandshake.CborPayloadBase64,
	}
	return output
}

// VerifyHandshake verifies the signature of the handshake along with the basic sanity checks
func VerifyHandshake(handshake *types.Handshake, userPublicKeyEd25519Base64 string) (bool, error) {
	// sanity checks
	if handshake.CborPayloadBase64 == "" || handshake.SignatureBase64 == "" || handshake.Content.OwnerPublicKeyBase64 == "" {
		return false, types.ErrBadRequest
	}

	cborPayload, dErr := base64.StdEncoding.DecodeString(handshake.CborPayloadBase64)
	if dErr != nil {
		return false, dErr
	}
	var content types.HandshakeContent
	cdErr := CborDecode(cborPayload, &content)
	if cdErr != nil {
		return false, cdErr
	}
	sig, sErr := base64.StdEncoding.DecodeString(handshake.SignatureBase64)
	if sErr != nil {
		return false, sErr
	}
	// keys must match
	if content.OwnerPublicKeyBase64 != userPublicKeyEd25519Base64 {
		return false, types.ErrSignatureInvalid
	}
	isValid, vErr := Verify(cborPayload, sig, content.OwnerPublicKeyBase64)
	if vErr != nil {
		return false, vErr
	}
	if !isValid {
		return false, types.ErrSignatureInvalid
	}
	return true, nil
}

// Encode message in Cbor format
func CborEncode(payload interface{}) ([]byte, error) {
	return cbor.Marshal(payload)
}

// Decode cbor message
func CborDecode(payload []byte, output interface{}) error {
	return cbor.Unmarshal(payload, output)
}

// Handshake from the server side (this is usually used when user has no handshake for specific sender)
func ServerSideHandshake(publicServerKey ed25519.PublicKey, privateServerKey ed25519.PrivateKey, domain string) (*types.Handshake, error) {

	// idContent := append(publicServerKey, []byte(senderAddress)...)
	// s256 := sha256.Sum256(idContent)

	addr, err := RawPublicKeyToMailioAddress(publicServerKey)
	if err != nil {
		return nil, err
	}

	ID := addr
	handshake := &types.Handshake{
		Content: types.HandshakeContent{
			HandshakeID: ID,
			OriginServer: types.HandshakeOriginServer{
				Domain: domain,
			},
			Type:                 types.HANDSHAKE_TYPE_SERVER,
			Status:               types.HANDSHAKE_STATUS_ACCEPTED,
			Level:                types.HANDSHAKE_LEVEL_NONE,
			OwnerPublicKeyBase64: base64.StdEncoding.EncodeToString(publicServerKey),
			OwnerAddressHex:      addr,
			Created:              float64(time.Now().UTC().UnixMilli()),
			SignatureScheme:      types.HANDSHAKE_SIGNATURE_SCHEME_EdDSA_X25519,
		},
	}
	cborPayload, cErr := CborEncode(handshake.Content)
	if cErr != nil {
		return nil, cErr
	}
	signature, sErr := Sign(cborPayload, privateServerKey)
	if sErr != nil {
		return nil, sErr
	}
	handshake.CborPayloadBase64 = base64.StdEncoding.EncodeToString(cborPayload)
	handshake.SignatureBase64 = base64.StdEncoding.EncodeToString(signature)
	return handshake, nil
}
