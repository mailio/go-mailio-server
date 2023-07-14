package types

type User struct {
	Email          string `json:"email" validate:"required,email"`
	EncryptedEmail string `json:"encryptedEmail" validate:"required"` // base64 scrypt encrypted email
	MailioAddress  string `json:"mailioAddress" validate:"required"`
	Created        int64  `json:"created" validate:"required"`
	Modified       int64  `json:"modified,omitempty"`
}

type EmailToMailioMapping struct {
	BaseDocument
	EncryptedEmail string `json:"encryptedEmail"`
	MailioAddress  string `json:"address"`
}
