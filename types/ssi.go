package types

import "github.com/mailio/go-mailio-core/did"

type DidDocument struct {
	BaseDocument `json:",inline"`
	DID          *did.Document `json:"did"`
}

type VerifiableCredentialDocument struct {
	BaseDocument `json:",inline"`
	VC           *did.VerifiableCredential `json:"vc"`
}
