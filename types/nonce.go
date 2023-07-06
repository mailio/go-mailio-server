package types

type Nonce struct {
	BaseDocument
	Nonce   string `json:"nonce"`
	Created int64  `json:"created"`
}
