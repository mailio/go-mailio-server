package types

type OutputBasicUserInfo struct {
	Address   string `json:"address"`
	TotalDisk int64  `json:"totalDisk,omitempty"`
	UsedDisk  int64  `json:"usedDisk,omitempty"`
	Created   int64  `json:"created,omitempty"`
}

type OutputUserAddress struct {
	Address string `json:"address"`
}

type DIDCommApiResponse struct {
	ID             string           `json:"id"`
	Type           string           `json:"type,omitempty"`
	MTPStatusCodes []*MTPStatusCode `json:"mtpStatusCodes,omitempty"`
}

type OutputDIDLookup struct {
	Found    []*DIDLookup `json:"found,omitempty"`
	NotFound []*DIDLookup `json:"notFound,omitempty"`
}
