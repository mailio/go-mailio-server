package types

// for login
type InputLogin struct {
	Email                         string `json:"email" validate:"required,email"`
	MailioAddress                 string `json:"mailioAddress" validate:"required"`
	Nonce                         string `json:"nonce" validate:"required"`
	Ed25519SigningPublicKeyBase64 string `json:"ed25519SigningPublicKeyBase64" validate:"required"` // public key of the private key used to sign the nonce
	SignatureBase64               string `json:"signatureBase64" validate:"required"`               // signature of Nonce string
}

// for register
type InputRegister struct {
	InputLogin
	DatabasePassword      string `json:"databasePassword" validate:"required"`      // this is a password for couchdbs private user database
	X25519PublicKeyBase64 string `json:"x25519PublicKeyBase64" validate:"required"` // public encryption key
}

// for DID resolution
type InputDID struct {
	DID string `json:"did" validate:"required"`
}

type InputHandshakeLookup struct {
	Lookups []HandshakeLookup `json:"lookups" validate:"min=1"`
}

type InputDIDLookup struct {
	Lookups []*DIDLookup `json:"lookups" validate:"min=1"`
}
