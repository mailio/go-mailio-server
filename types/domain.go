package types

type Domain struct {
	BaseDocument    `json:",inline"`
	Name            string `json:"name,omitempty"`
	IsMailioServer  bool   `json:"isMailioServer,omitempty"`
	MailioPublicKey string `json:"mailioPublicKey,omitempty"`
}
