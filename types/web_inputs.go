package types

// for login
type InputEmailPassword struct {
	Email                         string `json:"email" validate:"required,email"`
	Password                      string `json:"password" validate:"required"`
	MailioAddress                 string `json:"mailioAddress,omitempty"`
	Nonce                         string `json:"nonce,omitempty"`
	Ed25519SigningPublicKeyBase64 string `json:"ed25519SigningPublicKeyBase64,omitempty"` // public key of the private key used to sign the nonce
	SignatureBase64               string `json:"signatureBase64,omitempty"`               // signature of Nonce string
}

// for register
type InputRegister struct {
	InputEmailPassword
	X25519PublicKeyBase64 string `json:"x25519PublicKeyBase64" validate:"required"` // public encryption key
}

type InputDIDAuthLogin struct {
	Nonce     string `json:"nonce" validate:"required"`
	Signature string `json:"signature" validate:"required"`
	PublicKey string `json:"publicKey" validate:"required"`
}
