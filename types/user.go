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

type WebAuthnCredential struct {
	ID   []byte
	Name string
}

type WebAuhnUser struct {
	ID          []byte
	Name        string
	DisplayName string
	Credentials []WebAuthnCredential
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
func (u *WebAuhnUser) WebAuthnCredentials() []WebAuthnCredential {
	return u.Credentials
}

// Implementing the WebAuthnIcon method
func (u *WebAuhnUser) WebAuthnIcon() string {
	return u.Icon
}
