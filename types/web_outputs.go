package types

type OutputBasicUserInfo struct {
	Address     string        `json:"address"`
	TotalDisk   int64         `json:"totalDisk,omitempty"`
	UsedDisk    int64         `json:"usedDisk,omitempty"`
	DisplayName string        `json:"displayName,omitempty"`
	Picture     string        `json:"picture,omitempty"`
	Phone       string        `json:"phone,omitempty"`
	JobTitle    string        `json:"jobTitle,omitempty"`    // job title of the requester
	Company     string        `json:"company,omitempty"`     // company of the requester
	Description string        `json:"description,omitempty"` // description of the request
	Social      *MailioSocial `json:"social,omitempty"`      // social media links of the requester
	Created     int64         `json:"created,omitempty"`     // creation time
	WhatToShare string        `json:"whatToShare,omitempty"` // what the user wants to share from their personal data
}

type OutputUserAddress struct {
	Address string `json:"address"`
}

type DIDCommApiResponse struct {
	SmtpID         string           `json:"smtpId"`
	DIDCommID      string           `json:"didCommId"`
	Type           string           `json:"type,omitempty"`
	MTPStatusCodes []*MTPStatusCode `json:"mtpStatusCodes,omitempty"`
}

type OutputDIDLookup struct {
	Found    []*DIDLookup `json:"found,omitempty"`
	NotFound []*DIDLookup `json:"notFound,omitempty"`
}

type InterestOuput struct {
	MessageId string `json:"messageId,omitempty"`
}

type EmailStatisticsOutput struct {
	Received  int64 `json:"received"`
	Sent      int64 `json:"sent"`
	Interest  int64 `json:"interest"`
	SentByDay int64 `json:"sentByDay"`
}

type DeviceKeyTransferOutput struct {
	Nonce string `json:"nonce" validate:"required"`
}
