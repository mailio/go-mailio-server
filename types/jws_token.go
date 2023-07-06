package types

type JwsToken struct {
	Token string `json:"token"`
}

// When responding a nonce string as a signature challenge
type NonceResponse struct {
	Nonce string `json:"nonce"`
}
