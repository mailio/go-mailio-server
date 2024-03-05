package types

const (
	// Possible handshake types
	HANDSHAKE_TYPE_PERSONAL      = "personal"
	HANDSHAKE_TYPE_SIGNUP        = "signup"
	HANDSHAKE_TYPE_SERVER        = "server"
	HANDSHAKE_TYPE_USER_SPECIFIC = "user"

	// Possible handshake statuses
	HANDSHAKE_STATUS_ACCEPTED = "accepted"
	HANDSHAKE_STATUS_REVOKED  = "revoked"

	// Possbile handshake signup sub types
	HANDSHAKE_SIGNUP_SUBTYPE_TRANSACTIONAL = "transactional"
	HANDSHAKE_SIGNUP_SUBTYPE_PRODUCT       = "product"
	HANDSHAKE_SIGNUP_SUBTYPE_SECURITY      = "security"
	HANDSHAKE_SIGNUP_SUBTYPE_PROMOTION     = "promotion"
	HANDSHAKE_SIGNUP_SUBTYPE_NEWSLETTER    = "newsletter"
	HANDSHAKE_SIGNUP_SUBTYPE_REQUEST       = "request"
	HANDSHAKE_SIGNUP_SUBTYPE_OTHER         = "other"

	// Possible handshake levels
	HANDSHAKE_LEVEL_NONE         = "none"
	HANDSHAKE_LEVEL_RECAPTCHAV3  = "recaptchaV3"
	HANDSHAKE_LEVEL_POH          = "poh"      // proof of humanity
	HANDSHAKE_LEVEL_FACE_TO_FACE = "personal" // face to face created handshake

	// Possible signatures schemes
	HANDSHAKE_SIGNATURE_SCHEME_EdDSA_X25519 = "EdDSA_X25519"
)

/*
* Basic handshake structure which can be passed onto clients
 */
type Handshake struct {
	Content           HandshakeContent `json:"content"`
	SignatureBase64   string           `json:"signatureBase64"`
	CborPayloadBase64 string           `json:"cborPayloadBase64"` // payload in cbor format of handshake Content
}

type HandshakeOriginServer struct {
	Domain string `json:"domain" validate:"required"` // required
	IP     string `json:"ip,omitempty"`               // optional
}

type HandshakeSignupRules struct {
	FrequencyMinutes int `json:"frequencyMinutes,omitempty"` // optional
}

// Handshake is a struct that represents a handshake between two Mailio users or a Mailio user and a Mailio server
type HandshakeContent struct {
	HandshakeID          string                `json:"handshakeId,omitempty"`     // handshake ID
	OriginServer         HandshakeOriginServer `json:"originServer,omitempty"`    // origin server
	SignupSubType        *int                  `json:"signupSubType,omitempty"`   // handshake signup sub type
	SignupRules          *HandshakeSignupRules `json:"signupRules,omitempty"`     // handshake signup rules
	Status               string                `json:"status"`                    // handshake status
	Level                string                `json:"level"`                     // handshake level
	OwnerPublicKeyBase64 string                `json:"ownerPublicKey"`            // owner public key of the owner of the handshake
	OwnerAddressHex      string                `json:"ownerAddress"`              // mailio address of the owner of the handshake
	SenderMetadata       *SenderMetadata       `json:"senderMetadata,omitempty"`  // sender meta data (either Mailio address or sha512 email address )
	SignatureBase64      string                `json:"signatureBase64,omitempty"` // owners signature of the handshake
	Type                 string                `json:"type,omitempty"`            // handshake type
	SignatureScheme      string                `json:"signatureScheme"`           // handshake signature scheme
	Created              float64               `json:"created"`                   // timestamp of the handshake
}

// One of the emailHash or address MUST be present
type SenderMetadata struct {
	EmailHash string `json:"emailHash,omitempty"` // scrypt hash of the email address
	Address   string `json:"address,omitempty"`   // mailio address
}

// handshake is a struct that represents a handshake stored in the database
type StoredHandshake struct {
	BaseDocument      `json:",inline"`
	Content           HandshakeContent `json:"content"`
	OwnerAddress      string           `json:"ownerAddress"` // Mailio address of the owner of the handshake
	SignatureBase64   string           `json:"signatureBase64"`
	CborPayloadBase64 string           `json:"cborPayloadBase64"`
	Timestamp         int64            `json:"timestamp"` // timestamp of the handshake (created or updated)
}

type HandshakeLink struct {
	Link string `json:"link"`
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
	ID          string                `json:"id,omitempty"`
	Address     string                `json:"address,omitempty"`
	EmailHash   string                `json:"emailHash,omitempty"` // scrypt hash of the email address
	OriginSever HandshakeOriginServer `json:"originServer" validate:"required"`
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
	HandshakeHeader HandshakeHeader     `json:"handshakeHeader" validate:"required"`
	Handshakes      []*HandshakeContent `json:"handshakes" validate:"required"`
}

type HandshakeSignedResponse struct {
	HandshakeResponse HandshakeResponse `json:"handshakeResponse" validate:"required"`
	SignatureBase64   string            `json:"signatureBase64" validate:"required,base64"`
	CborPayloadBase64 string            `json:"cborPayloadBase64" validate:"required,base64"`
}
