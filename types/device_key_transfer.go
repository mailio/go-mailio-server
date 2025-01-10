package types

type DeviceKeyTransfer struct {
	BaseDocument            `json:",inline"`
	Address                 string `json:"address"`
	Email                   string `json:"email"`
	EncryptedSharedPassword string `json:"encryptedSharedPassword"`
	SmartKeyEncrypted       string `json:"smartKeyEncrypted,omitempty"`
	PasswordShare           string `json:"passwordShare,omitempty"`
	Created                 int64  `json:"created,omitempty"`
}
