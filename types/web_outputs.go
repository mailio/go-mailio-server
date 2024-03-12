package types

type OutputFindAddress struct {
	Address string `json:"address"`
}

type DIDCommApiResponse struct {
	ID             string           `json:"id"`
	Type           string           `json:"type,omitempty"`
	MTPStatusCodes []*MTPStatusCode `json:"mtpStatusCodes,omitempty"`
}
