package types

type User struct {
	Email          string `json:"email" validate:"required,email"`
	EncryptedEmail string `json:"encryptedEmail" validate:"required"` // base64 scrypt encrypted email
	Address        string `json:"address" validate:"required"`
	Created        int64  `json:"created" validate:"required"`
	Modified       int64  `json:"modified,omitempty"`
}
