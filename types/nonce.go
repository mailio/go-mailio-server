package types

type Nonce struct {
	BaseDocument `json:",inline"`
	Nonce        string `json:"nonce"`
	Created      int64  `json:"created"`
}
