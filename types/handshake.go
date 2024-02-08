package types

const (
	// Possible handshake types
	HANDSHAKE_TYPE_PERSONAL      = 0
	HANDSHAKE_TYPE_SIGNUP        = 1
	HANDSHAKE_TYPE_SERVER        = 2
	HANDSHAKE_TYPE_USER_SPECIFIC = 3

	// Possible handshake statuses
	HANDSHAKE_STATUS_ACCEPTED = 0
	HANDSHAKE_STATUS_REVOKED  = 1

	// Possbile handshake signup sub types
	HANDSHAKE_SIGNUP_SUBTYPE_TRANSACTIONAL = 0
	HANDSHAKE_SIGNUP_SUBTYPE_PRODUCT       = 1
	HANDSHAKE_SIGNUP_SUBTYPE_SECURITY      = 2
	HANDSHAKE_SIGNUP_SUBTYPE_PROMOTION     = 3
	HANDSHAKE_SIGNUP_SUBTYPE_NEWSLETTER    = 4
	HANDSHAKE_SIGNUP_SUBTYPE_REQUEST       = 5
	HANDSHAKE_SIGNUP_SUBTYPE_OTHER         = 6

	// Possible handshake levels
	HANDSHAKE_LEVEL_NONE         = 0
	HANDSHAKE_LEVEL_RECAPTCHAV3  = 1
	HANDSHAKE_LEVEL_POH          = 2 // proof of humanity
	HANDSHAKE_LEVEL_FACE_TO_FACE = 3 // face to face created handshake

	// Possible signatures schemes
	HANDSHAKE_SIGNATURE_SCHEME_EdDSA_X25519 = 0
)

/*
* Basic handshake structure which can be passed onto clients
 */
type Handshake struct {
	Content           HandshakeContent `json:"content"`
	SignatureBase64   string           `json:"signatureBase64"`
	CborPayloadBase64 string           `json:"cborPayloadBase64"`
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
	Status               int                   `json:"status"`                    // handshake status
	Level                int                   `json:"level"`                     // handshake level
	OwnerPublicKeyBase64 string                `json:"ownerPublicKey"`            // owner public key of the owner of the handshake
	OwnerAddressHex      string                `json:"ownerAddress"`              // mailio address of the owner of the handshake
	Sender               *HandshakeSender      `json:"sender,omitempty"`          // senders scrypted email address or mailio address + contact information
	SignatureBase64      string                `json:"signatureBase64,omitempty"` // owners signature of the handshake
	Type                 int                   `json:"type,omitempty"`            // handshake type
	SignatureScheme      int                   `json:"signatureScheme"`           // handshake signature scheme
	Created              int64                 `json:"timestamp"`                 // timestamp of the handshake
}

type HandshakeSender struct {
	Address       string `json:"address,omitempty"`       // senders scrypted email address or mailio address
	ScryptAddress string `json:"scryptAddress,omitempty"` // senders scrypted email address
	Name          string `json:"name,omitempty"`          // senders name
	Phone         string `json:"phone,omitempty"`         // senders phone
	Email         string `json:"email,omitempty"`         // senders email
}

// handshake is a struct that represents a handshake stored in the database
type StoredHandshake struct {
	BaseDocument      `json:",inline"`
	Content           HandshakeContent `json:"content"`
	SignatureBase64   string           `json:"signatureBase64"`
	CborPayloadBase64 string           `json:"cborPayloadBase64"`
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
	EmailHash   string                `json:"emailHash,omitempty"`
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
