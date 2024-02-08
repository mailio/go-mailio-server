package types

// DnsDiscovery is a Discovery that scans for DNS records.
type Discovery struct {
	// The domain name to query.
	Domain string `json:"domain"`
	// Ipsv4 addresses of the requested domain
	Ips []string `json:"ips"`
	// Flag telling if server  at domain supports mailio protocol
	IsMailio bool `json:"isMailio"`
	// Mailio base64 public key (if Mailio flag is true)
	PublicKey string `json:"publicKey,omitempty"`
	// The type of the public key (ed25519 support only at the moment)
	PublicKeyType string `json:"publicKeyType,omitempty"`
}
