package types

import (
	"github.com/go-webauthn/webauthn/webauthn"
)

type WebauthRegistrationVerify struct {
	AttestationResponse *WebauthnAttestationResponseJSON `json:"attestationResponse" validate:"required"`
	SmartKeyPayload     *SmartKeyPayload                 `json:"smartKeyPayload" validate:"required"`
}

type SmartKeyPayload struct {
	SmartKeyEncrypted       string `json:"smartKeyEncrypted" validate:"required"`       // encrypted pre-Shamir secret sharing
	PreRotatedMailioKey     string `json:"preRotatedMailioKey" validate:"required"`     // encypted pre-Shamir secret sharing
	Address                 string `json:"address" validate:"required"`                 // mailio address
	PasswordShare           string `json:"passwordShare" validate:"required"`           // a single share of a Shamir secret (2 out of 3 required for decryption)
	DatabasePassword        string `json:"databasePassword" validate:"required"`        // CoachDB password
	Email                   string `json:"email" validate:"required"`                   // email address
	PrimaryEd25519PublicKey string `json:"primaryEd25519PublicKey" validate:"required"` // primary Ed25519 public key (associated with address)
	PrimaryX25519PublicKey  string `json:"primaryX25519PublicKey" validate:"required"`  // primary X25519 public key (associated with address)
	ChallengeSignature      string `json:"challengeSignature" validate:"required"`      // signature of the challenge with the primary private key (held by client only)
	Challenge               string `json:"challenge" validate:"required"`               // challenge
}

// WebauthnAttestationResponseJSON is the JSON response from the Webauthn API
type WebauthnAttestationResponseJSON struct {
	ID                      string                      `json:"id"`
	RawID                   string                      `json:"rawId"`
	Type                    string                      `json:"type"`
	ClientExtensionResults  map[string]interface{}      `json:"clientExtensionResults,omitempty"`
	AuthenticatorAttachment string                      `json:"authenticatorAttachment"`
	Response                WebauthnAttestationResponse `json:"response"`
}

type WebauthnAttestationResponse struct {
	AttestationObject  string   `json:"attestationObject"`
	ClientDataJSON     string   `json:"clientDataJSON"`
	Transports         []string `json:"transports"`
	PublicKeyAlgorithm int      `json:"publicKeyAlgorithm"`
	PublicKey          string   `json:"publicKey"`
	AuthenticatorData  string   `json:"authenticatorData"`
}

type WebAuthnUserDB struct {
	BaseDocument `json:",inline"`
	Address      string                `json:"id"`          // maps to WebAuthNUser ID
	Name         string                `json:"name"`        // maps to WebAuthNUser Name
	DisplayName  string                `json:"displayName"` // maps to WebAuthNUser DisplayName
	Credentials  []webauthn.Credential `json:"credentials"` // maps to WebAuthNUser Credentials
	Icon         string                `json:"icon"`        // maps to WebAuthNUser Icon
}

func MapWebAuthnUserToDB(user WebAuhnUser) WebAuthnUserDB {
	return WebAuthnUserDB{
		Address:     string(user.ID),
		Name:        user.Name,
		DisplayName: user.DisplayName,
		Credentials: user.Credentials,
		Icon:        user.Icon,
	}
}

func MapWebAuthnUserFromDB(user WebAuthnUserDB) *WebAuhnUser {
	return &WebAuhnUser{
		ID:          []byte(user.Address),
		Name:        user.Name,
		DisplayName: user.DisplayName,
		Credentials: user.Credentials,
		Icon:        user.Icon,
	}
}

type WebAuhnUser struct {
	ID          []byte
	Name        string
	DisplayName string
	Credentials []webauthn.Credential
	Icon        string
}

// Implementing the WebAuthnID method
func (u *WebAuhnUser) WebAuthnID() []byte {
	return u.ID
}

// Implementing the WebAuthnName method
func (u *WebAuhnUser) WebAuthnName() string {
	return u.Name
}

// Implementing the WebAuthnDisplayName method
func (u *WebAuhnUser) WebAuthnDisplayName() string {
	return u.DisplayName
}

// Implementing the WebAuthnCredentials method
func (u *WebAuhnUser) WebAuthnCredentials() []webauthn.Credential {
	return u.Credentials
}

// Implementing the WebAuthnIcon method
func (u *WebAuhnUser) WebAuthnIcon() string {
	return u.Icon
}
