package types

// for login
type InputLogin struct {
	Email string `json:"email" validate:"required,email"`
	// Password                      string `json:"password,omitempty"`
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
