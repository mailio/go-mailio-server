package types

type MessageDelivery struct {
	BaseDocument  `json:",inline"`
	MessageID     string         `json:"messageId"`
	MTPStatusCode *MTPStatusCode `json:"code"`
	Created       int64          `json:"created"`
}
