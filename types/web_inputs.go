package types

// for login
type InputEmailPassword struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

// for register
type InputRegister struct {
	InputEmailPassword
	Address                       string `json:"address" validate:"required"`
	ReCaptchaV3Token              string `json:"reCaptchaV3Token" validate:"required"`
	X25519PublicKeyBase64         string `json:"x25519PublicKeyBase64" validate:"required"`
	Ed25519SigningPublicKeyBase64 string `json:"ed25519SigningPublicKeyBase64" validate:"required"`
	SignedEmailBase64             string `json:"signedEmail" validate:"required"` // signed email address as proof of owning a private key
}
