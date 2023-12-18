package types

import "github.com/mailio/go-mailio-core/models"

// handshake is a struct that represents a handshake stored in the database
type StoredHandshake struct {
	BaseDocument      `json:",inline"`
	Content           models.HandshakeContent `json:"content"`
	SignatureBase64   string                  `json:"signatureBase64"`
	CborPayloadBase64 string                  `json:"cborPayloadBase64"`
}

/****
* Mailio Transfer Protocol for Handshakes
****/
const (
	EmailLookupHashScheme_SC_N32768_R8_P1_L32_B64 = "SC_N32768_R8_P1_L32_B64"
	Signature_Scheme_EdDSA_X25519                 = "EdDSA_X25519"
)

type HandshakeHeader struct {
	SignatureScheme       string `json:"signatureScheme" validate:"required,oneof=EdDSA_X25519"`
	EmailLookupHashScheme string `json:"emailLookupHashScheme,omitempty"`
	Timestamp             int64  `json:"timestamp" validate:"required"`
}

type HandshakeLookup struct {
	ID        string `json:"id,omitempty"`
	Address   string `json:"address,omitempty"`
	EmailHash string `json:"emailHash,omitempty"`
}

type HandshakeRequest struct {
	HandshakeHeader              HandshakeHeader   `json:"handshakeHeader" validate:"required"`
	HandshakeLookups             []HandshakeLookup `json:"handshakeLookups" validate:"required"`
	ReturnDefaultServerHandshake bool              `json:"returnDefaultServerHandshake"`      // default false
	SenderAddress                string            `json:"senderAddress" validate:"required"` // intended senders Mailio address
}

type HandshakeSignedRequest struct {
	HandshakeRequest  HandshakeRequest `json:"handshakeRequest" validate:"required"`
	SignatureBase64   string           `json:"signatureBase64" validate:"required,base64"`
	CborPayloadBase64 string           `json:"cborPayloadBase64" validate:"required,base64"`
	SenderDomain      string           `json:"senderDomain" validate:"required"` // origin of the request (where DNS is published with Mailio public key)
}

type HandshakeResponse struct {
	HandshakeHeader HandshakeHeader            `json:"handshakeHeader" validate:"required"`
	Handshakes      []*models.HandshakeContent `json:"handshakes" validate:"required"`
}

type HandshakeSignedResponse struct {
	HandshakeResponse HandshakeResponse `json:"handshakeResponse" validate:"required"`
	SignatureBase64   string            `json:"signatureBase64" validate:"required,base64"`
	CborPayloadBase64 string            `json:"cborPayloadBase64" validate:"required,base64"`
}
