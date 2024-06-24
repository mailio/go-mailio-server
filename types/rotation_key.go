package types

// RotationKey is a struct that represents a rotation key
type RotationKey struct {
	BaseDocument            `json:",inline"`
	Address                 string `json:"address"`                 // mailio address
	PrimaryEd25519PublicKey string `json:"primaryEd25519PublicKey"` // primary Ed25519 public key (associated with address)
	PrimaryX25519PublicKey  string `json:"primaryX25519PublicKey"`  // primary X25519 public key (associated with address)
	ChallengeSignature      string `json:"challengeSignature"`      // signature of the challenge with the primary private key (held by client only)
	PreRotatedMailioKey     string `json:"preRotatedMailioKey"`     // aes encrypyted mailio key
	PasswordShare           string `json:"passwordShare"`           // a single share of a Shamir secret (2 out of 3 required for decryption)
	Email                   string `json:"email"`                   // email address
	Created                 int64  `json:"created"`                 // created timestamp
}
