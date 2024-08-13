package types

import (
	"github.com/mailio/go-mailio-did/did"
)

type DidDocument struct {
	BaseDocument `json:",inline"`
	DID          *did.Document `json:"did"`
}

type VerifiableCredentialDocument struct {
	BaseDocument `json:",inline"`
	VC           *did.VerifiableCredential `json:"vc"`
}

// DIDLookup from scrypted email address
type DIDLookup struct {
	EmailHash             string         `json:"emailHash" validate:"required"`   // scrypt hash of the email address
	Email                 string         `json:"email" validate:"required"`       // email address
	SupportsMailio        bool           `json:"supportsMailio,omitempty"`        // if the recipient supports Mailio (derived from domain resolving)
	SupportsStandardEmail bool           `json:"supportsStandardEmail,omitempty"` // if the recipient supports standard email (derrived from domain resolving)
	DIDDocument           *did.Document  `json:"didDocument,omitempty"`
	MTPStatusCode         *MTPStatusCode `json:"mtpStatusCode,omitempty"`
}

type DIDLookupRequest struct {
	SenderAddress string       `json:"senderAddress" validate:"required"` // intended senders Mailio address
	LookupHeader  LookupHeader `json:"lookupHeader" validate:"required"`
	DIDLookups    []*DIDLookup `json:"didLookups" validate:"required"`
}

type DIDLookupResponse struct {
	LookupHeader    LookupHeader `json:"lookupHeader" validate:"required"`
	FoundLookups    []*DIDLookup `json:"foundLookups,omitempty"`
	NotFoundLookups []*DIDLookup `json:"notFoundLookups,omitempty"`
}

type DIDDocumentSignedRequest struct {
	DIDLookupRequest  DIDLookupRequest `json:"didLookupRequest" validate:"required"`
	SignatureBase64   string           `json:"signatureBase64" validate:"required,base64"`
	CborPayloadBase64 string           `json:"cborPayloadBase64" validate:"required,base64"`
	SenderDomain      string           `json:"senderDomain" validate:"required"` // origin of the request (where DNS is published with Mailio public key)
}

type DIDDocumentSignedResponse struct {
	DIDLookupResponse DIDLookupResponse `json:"didLookupResponse" validate:"required"`
	SignatureBase64   string            `json:"signatureBase64" validate:"required,base64"`
	CborPayloadBase64 string            `json:"cborPayloadBase64" validate:"required,base64"`
}
