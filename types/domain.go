package types

// caching types of domains (smtp or/and mailio supported)
type Domain struct {
	BaseDocument           `json:",inline"`
	Name                   string `json:"name"`
	SupportsMailio         bool   `json:"supportsMailio"`            // domain can be both (mailio and smtp)
	MailioDIDDomain        string `json:"mailioDIDDomain,omitempty"` // mailio domain (if supportsMailio)
	SupportsStandardEmails bool   `json:"supportsStandardEmail"`     // domain can be both (mailio and smtp)
	MailioPublicKey        string `json:"mailioPublicKey,omitempty"`
	Timestamp              int64  `json:"timestamp"`
}

// user domain (which domain user is associated with)
type UserDomain struct {
	Name string `json:"name"`
	Type string `json:"type" oneOf:"smtp mailio"`
}
