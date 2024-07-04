package types

// RotationKey is a struct that represents a rotation key
type SmartKey struct {
	BaseDocument            `json:",inline"`
	Address                 string `json:"address" validate:"required"`                 // mailio address
	PrimaryEd25519PublicKey string `json:"primaryEd25519PublicKey" validate:"required"` // primary Ed25519 public key (associated with address)
	PrimaryX25519PublicKey  string `json:"primaryX25519PublicKey" validate:"required"`  // primary X25519 public key (associated with address)
	PreRotatedMailioKey     string `json:"preRotatedMailioKey" validate:"required"`     // aes encrypyted mailio key
	PasswordShare           string `json:"passwordShare" validate:"required"`           // a single share of a Shamir secret (2 out of 3 required for decryption)
	Email                   string `json:"email" validate:"required"`                   // email address
	SmartKeyEncrypted       string `json:"smartKeyEncrypted" validate:"required"`       // encrypted smart key
	Created                 int64  `json:"created"`                                     // created timestamp
}
