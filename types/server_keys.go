package types

type ServerKeys struct {
	Type       string `json:"type"`
	PublicKey  string `json:"publicKey"`
	PrivateKey string `json:"privateKey"`
}
